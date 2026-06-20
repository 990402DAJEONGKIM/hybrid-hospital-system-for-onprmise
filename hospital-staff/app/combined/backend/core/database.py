import os
import time
import logging
import threading
import psycopg2
from sqlalchemy import create_engine, text          # 260612 박경수: text 추가
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from fastapi import Depends, HTTPException, Request   # 260612 박경수: Request 추가
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

_sslmode = os.getenv("DB_SSLMODE", "require")

_cred_lock = threading.Lock()
_creds = {"user": None, "pw": None, "expires_at": 0.0}

REFRESH_MARGIN = 120  # 만료 2분 전 갱신

# 260612 박경수: JWT role_code → DB 그룹 롤 매핑 (화이트리스트)
ROLE_MAP = {
    "admin":   "role_admin",
    "doctor":  "role_doctor",
    "nurse":   "role_nurse",
    "patient": "role_patient",
    "auditor": "role_auditor",
}


def _fetch_new_creds():
    """Vault에서 새 dynamic credentials 발급. 실패 시 예외."""
    vault_addr = os.getenv("VAULT_ADDR", "")
    token_file = os.getenv("VAULT_TOKEN_FILE", "")
    if not (vault_addr and token_file and os.path.exists(token_file)):
        raise RuntimeError("VAULT_ADDR/VAULT_TOKEN_FILE 미설정")
    import hvac
    with open(token_file) as f:
        token = f.read().strip()
    client = hvac.Client(url=vault_addr, token=token)
    result = client.secrets.database.generate_credentials("onprem-api-role")
    now = time.time()
    with _cred_lock:
        _creds["user"] = result["data"]["username"]
        _creds["pw"] = result["data"]["password"]
        _creds["expires_at"] = now + result["lease_duration"]
    logger.info("Vault DB 크레덴셜 갱신: %s (TTL %ds)",
                result["data"]["username"], result["lease_duration"])


def _make_connection():
    """creator: 캐시된 크레덴셜로 연결. 새 lease 발급 안 함."""
    with _cred_lock:
        user, pw = _creds["user"], _creds["pw"]
    if not user:
        # 캐시가 비면 Vault에서 직접 발급. 실패 시 예외를 그대로 전파.
        # (DATABASE_URL fallback 제거 — 죽은 정적 크레덴셜로 조용히 빠지는 사고 방지)
        _fetch_new_creds()
        with _cred_lock:
            user, pw = _creds["user"], _creds["pw"]
    kwargs = dict(host="127.0.0.1", port=5432, dbname="hospital",
                  user=user, password=pw)
    if _sslmode != "disable":
        kwargs["sslmode"] = _sslmode
    return psycopg2.connect(**kwargs)


# engine은 모듈 로드 시 1회 생성, 이후 재생성 없음
engine = create_engine(
    "postgresql+psycopg2://",
    creator=_make_connection,
    pool_pre_ping=True,
    pool_size=5,
    max_overflow=10,
    pool_recycle=1800,
)
read_engine = create_engine(
    "postgresql+psycopg2://",
    creator=_make_connection,
    pool_pre_ping=True,
    pool_size=5,
    max_overflow=10,
    pool_recycle=1800,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
ReadSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=read_engine)

# ── RDS 이중 쓰기 엔진 (퇴원 지시 동기화용) ──────────────────────
# RDS_HOST 미설정 시 None으로 유지 → 엔드포인트에서 graceful skip
_rds_host = os.getenv("RDS_HOST", "")
_rds_port = int(os.getenv("RDS_PORT", "5432"))
_rds_db   = os.getenv("RDS_DBNAME", "hospital")
_rds_user = os.getenv("RDS_USER",   "")
_rds_pass = os.getenv("RDS_PASSWORD", "")

if _rds_host and _rds_user:
    _rds_url = (
        f"postgresql+psycopg2://{_rds_user}:{_rds_pass}"
        f"@{_rds_host}:{_rds_port}/{_rds_db}"
    )
    rds_engine = create_engine(
        _rds_url,
        pool_pre_ping=True,
        pool_size=3,
        max_overflow=5,
        pool_recycle=1800,
    )
    RdsSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=rds_engine)
else:
    rds_engine      = None
    RdsSessionLocal = None


def get_rds_db():
    """RDS 이중 쓰기용 세션 — RDS_HOST 미설정 시 None yield."""
    if RdsSessionLocal is None:
        yield None
        return
    db = RdsSessionLocal()
    try:
        yield db
    finally:
        try:
            db.close()
        except Exception:
            pass


class Base(DeclarativeBase):
    pass


def rotate_credentials():
    """새 크레덴셜 발급 + 옛 유저로 맺은 풀 연결 전부 폐기"""
    _fetch_new_creds()
    engine.dispose()
    read_engine.dispose()
    logger.info("DB 커넥션 풀 폐기 완료, 다음 연결부터 새 크레덴셜 사용")


def _cred_refresh_loop():
    while True:
        with _cred_lock:
            expires_at = _creds["expires_at"]
        sleep_sec = max(expires_at - time.time() - REFRESH_MARGIN, 30)
        time.sleep(sleep_sec)
        try:
            rotate_credentials()
        except Exception:
            logger.exception("크레덴셜 로테이션 실패, 30초 후 재시도")
            time.sleep(30)


_refresher_started = False

def start_cred_refresher():
    global _refresher_started
    if _refresher_started:
        return
    _refresher_started = True
    try:
        _fetch_new_creds()
    except Exception as e:
        logger.warning("시작 시 Vault 크레덴셜 발급 실패 (fallback으로 동작): %s", e)
    threading.Thread(target=_cred_refresh_loop, daemon=True,
                     name="vault-cred-refresh").start()
    logger.info("Vault 크레덴셜 백그라운드 갱신 스레드 시작")





# ============================================================
# 260612 박경수: RLS enforce — 세션 의존성들
# ============================================================



# 260612 박경수: 순환 import 회피 — get_current_user를 요청 시점에 지연 호출하는 래퍼.
# (Depends에 직접/lambda기본값으로 넣으면 정의 시점에 security를 import하려다 순환 발생)
def _resolve_current_user(request: Request):
    from core.security import decode_access_token
    access_token = request.cookies.get("access_token")
    if not access_token:
        raise HTTPException(status_code=401, detail="로그인이 필요합니다.")
    return decode_access_token(access_token)


def _apply_role(db, current_user: dict):
    """세션에 사용자 role + RLS 컨텍스트 주입."""
    role = ROLE_MAP.get(current_user.get("role"))
    if role is None:
        raise HTTPException(status_code=403, detail="알 수 없는 역할입니다.")
    db.execute(text(f"SET ROLE {role}"))   # role은 화이트리스트값 → 인젝션 불가
    db.execute(text("SELECT set_config('app.current_doctor_id',  :v, false)")
               .bindparams(v=current_user.get("did") or ""))
    db.execute(text("SELECT set_config('app.current_patient_id', :v, false)")
               .bindparams(v=current_user.get("pid") or ""))


def _reset_role(db):
    """풀 반환 전 원복 — 커넥션 재사용 시 role 누수 차단."""
    try:
        db.rollback()  # aborted 트랜잭션 상태 먼저 클리어 (RESET ROLE 실행 가능하게)
        db.execute(text("RESET ROLE"))
        db.execute(text("SELECT set_config('app.current_doctor_id', '', false)"))
        db.execute(text("SELECT set_config('app.current_patient_id', '', false)"))
        db.commit()
    except Exception:
        db.rollback()


def _set_role_with_retry(db, role: str, factory):
    """SET ROLE 실패(크레덴셜 만료 등) 시 재발급 후 1회 재시도."""
    try:
        db.execute(text(f"SET ROLE {role}"))
    except Exception as e:
        if "permission denied" in str(e).lower():
            logger.warning("SET ROLE %s 실패 — 크레덴셜 재발급 후 재시도: %s", role, e)
            db.close()
            rotate_credentials()
            db = factory()
            db.execute(text(f"SET ROLE {role}"))
        else:
            raise
    return db


def get_db(current_user: dict = Depends(_resolve_current_user)):
    db = SessionLocal()
    try:
        try:
            _apply_role(db, current_user)
        except Exception as e:
            if "permission denied" in str(e).lower():
                logger.warning("_apply_role 실패 — 크레덴셜 재발급 후 재시도: %s", e)
                db.close()
                rotate_credentials()
                db = SessionLocal()
                _apply_role(db, current_user)
            else:
                raise
        yield db
    finally:
        _reset_role(db)
        db.close()


def get_read_db(current_user: dict = Depends(_resolve_current_user)):
    db = ReadSessionLocal()
    try:
        try:
            _apply_role(db, current_user)
        except Exception as e:
            if "permission denied" in str(e).lower():
                logger.warning("_apply_role(read) 실패 — 크레덴셜 재발급 후 재시도: %s", e)
                db.close()
                rotate_credentials()
                db = ReadSessionLocal()
                _apply_role(db, current_user)
            else:
                raise
        yield db
    finally:
        _reset_role(db)
        db.close()


# 인증 엔드포인트 전용 — 로그인 시점엔 current_user 없음. role_admin 고정.
def get_auth_db():
    db = _set_role_with_retry(SessionLocal(), "role_admin", SessionLocal)
    try:
        yield db
    finally:
        _reset_role(db)
        db.close()


# break-glass(긴급 접근) 전용 — 의도적 RLS 우회. BREAK_GLASS_ACCESS로 감사.
def get_breakglass_db():
    db = _set_role_with_retry(SessionLocal(), "role_admin", SessionLocal)
    try:
        yield db
    finally:
        _reset_role(db)
        db.close()