import re
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DbSession

from core.database import get_db, get_auth_db   # 260612 박경수: get_auth_db 추가
from core.security import (
    COOKIE_SECURE,
    create_access_token, generate_refresh_token,
    get_current_user, hash_password, sha256_hex,
    verify_api_key, verify_password,
)
from models.db import Role, Session as SessionModel, SyncPatient, User

router = APIRouter(prefix="/auth", tags=["auth"])

ACCESS_TOKEN_EXPIRE_SECONDS = 1800
REFRESH_TOKEN_EXPIRE_HOURS  = 8
MAX_FAILED_LOGINS           = 5
LOCKOUT_MINUTES             = 30
PASSWORD_EXPIRE_DAYS        = 90


# ── Pydantic 스키마 ─────────────────────────────────────────

class LoginRequest(BaseModel):
    member_number: str
    password:      str

class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str


# ── 비밀번호 정책 검증 (ISMS-P 2.5.3) ──────────────────────

def validate_password(password: str) -> str | None:
    has_upper   = bool(re.search(r'[A-Z]', password))
    has_lower   = bool(re.search(r'[a-z]', password))
    has_digit   = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[!@#$%^&*()\-_=+\[\]{};:\'",.<>?/\\|`~]', password))
    kinds = sum([has_upper, has_lower, has_digit, has_special])

    if len(password) < 8:
        return "8자 이상 입력해주세요."
    if kinds < 2:
        return "영문·숫자·특수문자 중 2종류 이상을 포함해야 합니다."
    if kinds == 2 and len(password) < 10:
        return "2종류 조합 시 10자 이상 입력해주세요."
    return None


def _build_token_payload(user: User) -> dict:
    import os
    payload = {"sub": str(user.user_id), "role": user.role_ref.role_code}
    # DB_MODE 분기: 온프레미스는 patient_id UUID, 클라우드는 patient_id_hash varchar — by 김다정, 2026-06-06
    if os.getenv("DB_MODE", "cloud") == "onprem":
        pid = getattr(user, "patient_id", None)
        if pid:
            payload["pid"] = str(pid)
    else:
        pid = getattr(user, "patient_id_hash", None)
        if pid:
            payload["pid"] = pid
    if user.doctor_id:
        payload["did"] = str(user.doctor_id)
    return payload


# ── 엔드포인트 ──────────────────────────────────────────────


@router.post("/login")
def login(
    body:    LoginRequest,
    request: Request,
    db:      DbSession = Depends(get_auth_db),  # 260612 박경수: get_db → get_auth_db
    _:       str       = Depends(verify_api_key),
):
    user = db.query(User).filter(User.member_number == body.member_number).first()
    if not user:
        raise HTTPException(status_code=401, detail="회원번호 또는 비밀번호가 올바르지 않습니다.")

    now = datetime.now(timezone.utc)

    if user.locked_until and user.locked_until > now:
        remaining = int((user.locked_until - now).total_seconds() / 60)
        raise HTTPException(
            status_code=401,
            detail=f"계정이 잠겨 있습니다. {remaining}분 후 재시도하세요.",
        )

    if not verify_password(body.password, user.password_hash):
        user.failed_login_cnt += 1
        if user.failed_login_cnt >= MAX_FAILED_LOGINS:
            user.locked_until = now + timedelta(minutes=LOCKOUT_MINUTES)
        db.commit()
        raise HTTPException(status_code=401, detail="회원번호 또는 비밀번호가 올바르지 않습니다.")

    user.failed_login_cnt = 0
    user.locked_until     = None
    user.last_login_at    = now

    access_token  = create_access_token(_build_token_payload(user), ACCESS_TOKEN_EXPIRE_SECONDS)
    refresh_token = generate_refresh_token()

    db.add(SessionModel(
        user_id            = user.user_id,
        refresh_token_hash = sha256_hex(refresh_token),
        user_agent         = request.headers.get("user-agent"),
        ip_address         = request.client.host if request.client else None,
        expires_at         = now + timedelta(hours=REFRESH_TOKEN_EXPIRE_HOURS),
    ))
    db.commit()

    response = JSONResponse({
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_SECONDS,
    })
    _set_auth_cookies(response, access_token, refresh_token)
    return response


def _set_auth_cookies(response: Response, access_token: str, refresh_token: str) -> None:
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="strict",
        max_age=ACCESS_TOKEN_EXPIRE_SECONDS,
        path="/",
    )
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="strict",
        max_age=REFRESH_TOKEN_EXPIRE_HOURS * 3600,
        path="/api/portal/auth/refresh",
    )


@router.post("/refresh")
def refresh(
    request: Request,
    db:      DbSession = Depends(get_auth_db),  # 260612 박경수: get_db → get_auth_db
    _:       str       = Depends(verify_api_key),
):
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        raise HTTPException(status_code=401, detail="유효하지 않은 세션입니다. 다시 로그인하세요.")

    now        = datetime.now(timezone.utc)
    token_hash = sha256_hex(refresh_token)

    session = db.query(SessionModel).filter(
        SessionModel.refresh_token_hash == token_hash,
    ).first()

    # 만료·폐기된 토큰으로 재시도 → 탈취 의심, 해당 계정 전체 세션 폐기
    if not session or session.is_revoked or session.expires_at < now:
        if session and not session.is_revoked:
            db.query(SessionModel).filter(
                SessionModel.user_id == session.user_id
            ).update({"is_revoked": True})
            db.commit()
        raise HTTPException(status_code=401, detail="유효하지 않은 세션입니다. 다시 로그인하세요.")

    user = db.query(User).filter(User.user_id == session.user_id).first()

    session.is_revoked = True  # 기존 토큰 폐기 (Rotation)

    new_access_token  = create_access_token(_build_token_payload(user), ACCESS_TOKEN_EXPIRE_SECONDS)
    new_refresh_token = generate_refresh_token()

    db.add(SessionModel(
        user_id            = user.user_id,
        refresh_token_hash = sha256_hex(new_refresh_token),
        expires_at         = now + timedelta(hours=REFRESH_TOKEN_EXPIRE_HOURS),
    ))
    db.commit()

    response = JSONResponse({"token_type": "bearer", "expires_in": ACCESS_TOKEN_EXPIRE_SECONDS})
    _set_auth_cookies(response, new_access_token, new_refresh_token)
    return response


@router.post("/logout", status_code=204)
def logout(
    request: Request,
    response: Response,
    db:       DbSession = Depends(get_auth_db),  # 260612 박경수: get_db → get_auth_db
    _:        str       = Depends(verify_api_key),
):
    refresh_token = request.cookies.get("refresh_token")
    if refresh_token:
        session = db.query(SessionModel).filter(
            SessionModel.refresh_token_hash == sha256_hex(refresh_token),
        ).first()
        if session:
            session.is_revoked = True
            db.commit()
    response.delete_cookie(key="access_token",  path="/")
    response.delete_cookie(key="refresh_token", path="/api/portal/auth/refresh")


@router.get("/me")
def me(
    current_user: dict     = Depends(get_current_user),
    db:           DbSession = Depends(get_db),
):
    user = db.query(User).filter(User.user_id == current_user["sub"]).first()
    if not user:
        raise HTTPException(status_code=401, detail="사용자를 찾을 수 없습니다.")

    now             = datetime.now(timezone.utc)
    password_expired = (
        (now - user.password_changed_at).days >= PASSWORD_EXPIRE_DAYS
        if user.password_changed_at else False
    )

    result = {
        "user_id":             str(user.user_id),
        "role":                user.role_ref.role_code,
        "password_expired":    password_expired,
        "password_expire_days": PASSWORD_EXPIRE_DAYS,
    }
    # DB_MODE 분기: 클라우드만 patient_id_hash 반환 — by 김다정, 2026-06-06
    pid_hash = getattr(user, "patient_id_hash", None)
    if pid_hash:
        result["patient_id_hash"] = pid_hash
    return result


@router.post("/change-password", status_code=204)
def change_password(
    body:         ChangePasswordRequest,
    response:     Response,
    current_user: dict      = Depends(get_current_user),
    db:           DbSession = Depends(get_db),
):
    user = db.query(User).filter(User.user_id == current_user["sub"]).first()

    if not verify_password(body.old_password, user.password_hash):
        raise HTTPException(status_code=400, detail="현재 비밀번호가 올바르지 않습니다.")

    pw_error = validate_password(body.new_password)
    if pw_error:
        raise HTTPException(status_code=400, detail=pw_error)

    user.password_hash       = hash_password(body.new_password)
    user.password_changed_at = datetime.now(timezone.utc)

    # 비밀번호 변경 시 기존 세션 전체 폐기 (탈취된 토큰 무력화)
    db.query(SessionModel).filter(
        SessionModel.user_id    == user.user_id,
        SessionModel.is_revoked == False,
    ).update({"is_revoked": True})

    db.commit()

    response.delete_cookie(key="access_token",  path="/")
    response.delete_cookie(key="refresh_token", path="/api/portal/auth/refresh")
