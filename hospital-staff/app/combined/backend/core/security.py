import os
import uuid
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from jose import jwt, JWTError
from passlib.context import CryptContext
from fastapi import Cookie, HTTPException, Request, Security, Depends
from fastapi.security import APIKeyHeader
from dotenv import load_dotenv
from sqlalchemy.orm import Session
from models.db import User, Role, Permission, RolePermission

# DB 정책 로드 실패 시 사용되는 안전 기본값
_DEFAULT_MAX_FAILED     = 5
_DEFAULT_LOCKOUT_MIN    = 30
_DEFAULT_PW_EXPIRE_DAYS = 90

load_dotenv()

JWT_SECRET          = os.getenv("JWT_SECRET", "")           # Vault에서 주입 필수 — 빈 값이면 JWT 검증 실패
JWT_SECRET_PREVIOUS = os.getenv("JWT_SECRET_PREVIOUS", "")  # 키 교체 grace period용
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
API_KEY       = os.getenv("API_KEY", "")
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "true").lower() == "true"

pwd_context    = CryptContext(schemes=["bcrypt", "argon2"], deprecated="auto")
api_key_header = APIKeyHeader(name="X-API-Key")


def reload_jwt_secrets() -> None:
    """vault_loader.py가 os.environ에 주입한 뒤 호출 — 모듈 수준 변수를 갱신.

    Python 모듈 변수는 임포트 시점에 평가되므로,
    Vault 로드 이후 이 함수를 명시적으로 호출해야 반영됩니다.
    """
    global JWT_SECRET, JWT_SECRET_PREVIOUS, API_KEY
    JWT_SECRET          = os.getenv("JWT_SECRET", "")
    JWT_SECRET_PREVIOUS = os.getenv("JWT_SECRET_PREVIOUS", "")
    API_KEY             = os.getenv("API_KEY", "")


def get_client_ip(request: Request) -> Optional[str]:
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else None


def verify_api_key(key: str = Security(api_key_header)) -> str:
    if key != API_KEY:
        raise HTTPException(status_code=403, detail="유효하지 않은 API 키입니다.")
    return key


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def encrypt_national_id(plain: str) -> str:
    from cryptography.fernet import Fernet
    key = os.getenv("NATIONAL_ID_ENC_KEY", "").encode()
    if not key:
        raise RuntimeError("NATIONAL_ID_ENC_KEY 환경변수가 설정되지 않았습니다.")
    return Fernet(key).encrypt(plain.encode()).decode()


def decrypt_national_id(token: str) -> str:
    from cryptography.fernet import Fernet
    key = os.getenv("NATIONAL_ID_ENC_KEY", "").encode()
    if not key:
        raise RuntimeError("NATIONAL_ID_ENC_KEY 환경변수가 설정되지 않았습니다.")
    return Fernet(key).decrypt(token.encode()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def generate_refresh_token() -> str:
    return secrets.token_urlsafe(48)


def create_access_token(payload: dict, expires_in: int = 1800) -> str:
    now  = datetime.now(timezone.utc)
    data = {**payload, "iat": now, "exp": now + timedelta(seconds=expires_in)}
    return jwt.encode(data, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> dict:
    for secret in filter(None, [JWT_SECRET, JWT_SECRET_PREVIOUS]):
        try:
            return jwt.decode(token, secret, algorithms=[JWT_ALGORITHM])
        except JWTError:
            continue
    raise HTTPException(status_code=401, detail="유효하지 않은 인증입니다. 다시 로그인하세요.")

    # 260601 박경수 수정 - JWT_SECRET과 JWT_SECRET_PREVIOUS 모두 실패 시 401 예외 발생하도록 변경


def get_current_user(
    access_token: str | None = Cookie(default=None),
    _: str = Depends(verify_api_key),
) -> dict:
    if not access_token:
        raise HTTPException(status_code=401, detail="로그인이 필요합니다.")
    return decode_access_token(access_token)


def has_permission(user_id: str, permission_code: str, db: Session) -> bool:
    """사용자의 역할이 특정 권한 코드를 가지고 있는지 확인 (ISMS-P 2.5.4)"""
    return db.query(Permission).join(RolePermission).join(Role).join(User).\
        filter(User.user_id == user_id, Permission.permission_code == permission_code).count() > 0


def require_permission(permission_code: str):
    """FastAPI Depends 팩토리. 권한 없으면 403 반환."""
    from core.database import get_db

    def _dependency(
        current_user: dict = Depends(get_current_user),
        db:           Session = Depends(get_db),
    ) -> dict:
        if not has_permission(current_user["sub"], permission_code, db):
            raise HTTPException(status_code=403, detail="접근 권한이 없습니다.")
        return current_user

    return _dependency


# ── 비밀번호 정책 ────────────────────────────────────────────────

def get_password_policy(db: Session):
    """password_policy 테이블에서 정책 로드. 행이 없으면 기본값 객체 반환."""
    from models.db import PasswordPolicy
    policy = db.query(PasswordPolicy).first()
    if policy:
        return policy
    from types import SimpleNamespace
    return SimpleNamespace(
        max_failed_logins = _DEFAULT_MAX_FAILED,
        lockout_minutes   = _DEFAULT_LOCKOUT_MIN,
        expire_days       = _DEFAULT_PW_EXPIRE_DAYS,
        min_length        = 8,
        require_uppercase = True,
        require_lowercase = True,
        require_digit     = True,
        require_special   = True,
    )


# ── 감사 로그 (ISMS-P 2.9.1) ────────────────────────────────────

# 260612 박경수: RLS enforce 대응 — audit_logs 직접 INSERT는 role_* 권한 없어 실패.
# log_audit() SECURITY DEFINER 함수 경유로 role 무관하게 안전 기록.
# (온프레미스 전용: patient_id는 UUID. cloud 분기 제거 — onprem만 운영)
def record_audit(
    db:           Session,
    action_type:  str,
    result_code:  str,
    user_id=None,
    patient_id=None,
    target_table: Optional[str] = None,
    target_id=None,
    source_ip:    Optional[str] = None,
) -> None:
    """audit_logs 단일 행 기록. log_audit() 함수 경유.
    예외가 나도 메인 트랜잭션을 끊지 않는다."""
    from sqlalchemy import text
    try:
        with db.begin_nested():
            db.execute(
                text(
                    "SELECT log_audit("
                    "CAST(:user_id AS uuid), CAST(:patient_id AS uuid), :action, "
                    ":target_table, CAST(:target_id AS uuid), CAST(:source_ip AS inet), :result)"
                ),
                {
                    "user_id":      str(user_id) if user_id else None,
                    "patient_id":   str(patient_id) if patient_id else None,
                    "action":       action_type,
                    "target_table": target_table,
                    "target_id":    str(target_id) if target_id else None,
                    "source_ip":    source_ip,
                    "result":       result_code,
                },
            )
    except Exception:
        pass  # 감사 로그 실패가 비즈니스 흐름을 막으면 안 됨


# ── 로그인 이력 (ISMS-P 2.5.1) ──────────────────────────────────

def record_login_history(
    db:         Session,
    result:     str,           # 'success' | 'fail' | 'locked'
    email:      Optional[str] = None,
    user_id=None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> None:
    """login_history 테이블에 단일 행 삽입."""
    from models.db import LoginHistory
    try:
        db.add(LoginHistory(
            user_id    = user_id,
            email      = email,
            result     = result,
            ip_address = ip_address,
            user_agent = user_agent,
        ))
    except Exception:
        pass
