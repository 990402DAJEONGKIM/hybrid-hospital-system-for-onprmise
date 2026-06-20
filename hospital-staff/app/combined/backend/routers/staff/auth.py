import re
import uuid
from datetime import datetime, timedelta, timezone

import pyotp
from cryptography.fernet import Fernet

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DbSession

from core.database import get_db, get_auth_db  # 260612 박경수: import 추가

from core.security import (
    COOKIE_SECURE,
    create_access_token, generate_refresh_token,
    get_client_ip, get_current_user, get_password_policy,
    hash_password, sha256_hex,
    verify_api_key, verify_password,
)
from core.ses import send_lockout_alert
import os

from models.db import (
    AuditLog, LoginHistory, Menu, OnpremDepartment, OnpremDoctor,
    Role, RoleMenu, Session as SessionModel,
    SyncDepartment, SyncDoctor, User, UserMfa,
)

_DB_MODE = os.getenv("DB_MODE", "cloud")

router = APIRouter(prefix="/auth", tags=["auth"])

ACCESS_TOKEN_EXPIRE_SECONDS  = 1800
REFRESH_TOKEN_EXPIRE_HOURS   = 8
MFA_PENDING_EXPIRE_SECONDS   = 300  # 5분


def _get_fernet() -> Fernet:
    key = os.getenv("MFA_ENC_KEY", "")
    if not key:
        raise HTTPException(status_code=500, detail="MFA 암호화 키가 설정되지 않았습니다.")
    return Fernet(key.encode())


def _encrypt_totp_secret(plain: str) -> str:
    return _get_fernet().encrypt(plain.encode()).decode()


def _decrypt_totp_secret(encrypted: str) -> str:
    return _get_fernet().decrypt(encrypted.encode()).decode()


# ── Pydantic 스키마 ─────────────────────────────────────────

class RegisterRequest(BaseModel):
    member_number: str
    password:      str
    role_code:     str   # 'doctor' | 'nurse' | 'admin'

class LoginRequest(BaseModel):
    member_number: str
    password:      str

class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str

class MfaVerifyRequest(BaseModel):
    code: str

class MfaSetupVerifyRequest(BaseModel):
    code: str


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

# 260612 박경수: RLS enforce 대응 — 직접 INSERT 제거, 공통 record_audit(log_audit 경유) 사용
def _record_audit(db: DbSession, user_id: uuid.UUID | None, action: str, result: str, request: Request, patient_id=None):
    """감사 로그 기록 (ISMS-P 2.9.1)"""
    from core.security import record_audit
    record_audit(
        db,
        action_type = action,
        result_code = result,
        user_id     = user_id,
        patient_id  = patient_id,
        source_ip   = get_client_ip(request),
    )
    db.commit()


def _build_token_payload(user: User) -> dict:
    import os
    payload = {
        "sub":  str(user.user_id),
        "role": user.role_ref.role_code,
    }
    # DB_MODE 분기: 클라우드는 patient_id_hash, 온프레미스는 patient_id UUID — by 김다정, 2026-06-06
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

@router.post("/register", status_code=201)
def register(
    body:    RegisterRequest,
    request: Request,
    db:      DbSession = Depends(get_auth_db),   # 260612 박경수: get_db → get_auth_db
    _:       str       = Depends(verify_api_key),
    current_user: dict = Depends(get_current_user),
):
    """스태프 계정 생성 — admin 역할만 허용 (5단계: 관리자 화면에서 호출)."""
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="관리자만 스태프 계정을 생성할 수 있습니다.")

    ALLOWED_ROLES = {"doctor", "nurse", "admin"}
    if body.role_code not in ALLOWED_ROLES:
        raise HTTPException(status_code=400, detail=f"허용된 역할: {', '.join(sorted(ALLOWED_ROLES))}")

    pw_error = validate_password(body.password)
    if pw_error:
        raise HTTPException(status_code=400, detail=pw_error)

    role = db.query(Role).filter(Role.role_code == body.role_code, Role.is_active == True).first()
    if not role:
        raise HTTPException(status_code=400, detail="유효하지 않은 역할 코드입니다.")

    if db.query(User).filter(User.member_number == body.member_number).first():
        raise HTTPException(status_code=400, detail="이미 사용 중인 회원번호입니다.")

    user = User(
        member_number = body.member_number,
        password_hash = hash_password(body.password),
        role_id       = role.role_id,
    )
    db.add(user)
    try:
        db.commit()
        db.refresh(user)
        _record_audit(db, user.user_id, "STAFF_REGISTER", "201", request)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=400, detail="이미 계정이 존재합니다.")

    return {
        "user_id":   str(user.user_id),
        "role_code": role.role_code,
        "message":   "스태프 계정이 생성되었습니다.",
    }


@router.post("/login")
def login(
    body:    LoginRequest,
    request: Request,
    db:      DbSession = Depends(get_auth_db),   # 260612 박경수: get_db → get_auth_db
    _:       str       = Depends(verify_api_key),
):
    # 로그인 시도 기록 준비 (ISMS-P 2.9.1)
    history = LoginHistory(email=body.member_number, ip_address=get_client_ip(request), user_agent=request.headers.get("user-agent"))

    user = db.query(User).filter(User.member_number == body.member_number).first()
    if not user:
        history.result = "fail"
        db.add(history)
        db.commit()
        raise HTTPException(status_code=401, detail="회원번호 또는 비밀번호가 올바르지 않습니다.")

    now = datetime.now(timezone.utc)

    if not user.is_active:
        history.user_id = user.user_id
        history.result = "fail"
        db.add(history)
        db.commit()
        raise HTTPException(status_code=401, detail="비활성화된 계정입니다. 관리자에게 문의하세요.")

    if user.locked_until and user.locked_until > now:
        history.user_id = user.user_id
        history.result = "locked"
        db.add(history)
        db.commit()
        remaining = max(1, int((user.locked_until - now).total_seconds() / 60))
        raise HTTPException(status_code=401, detail=f"계정이 잠겨 있습니다. {remaining}분 후 재시도하세요.")

    if not verify_password(body.password, user.password_hash):
        policy = get_password_policy(db)
        history.user_id = user.user_id
        history.result = "fail"
        user.failed_login_cnt += 1
        if user.failed_login_cnt >= policy.max_failed_logins:
            user.locked_until = now + timedelta(minutes=policy.lockout_minutes)
            history.result = "locked"
            _record_audit(db, user.user_id, "ACCOUNT_LOCKED", "401", request)
            send_lockout_alert(
                target_email = user.email,
                ip_address   = get_client_ip(request),
                locked_until = user.locked_until.isoformat(),
            )
        db.add(history)
        db.commit()
        raise HTTPException(status_code=401, detail="회원번호 또는 비밀번호가 올바르지 않습니다.")

    # 성공 기록
    # log_audit() PostgreSQL 함수가 내부에서 SET ROLE을 리셋함 → _record_audit 이후 DB 작업 불가
    # 해결: commit 전에 필요한 값 캡처 → 주요 DB 작업을 먼저 한 번에 commit → 감사 로그는 마지막
    token_payload = _build_token_payload(user)
    user_id       = user.user_id

    user.failed_login_cnt = 0
    user.locked_until     = None
    user.last_login_at    = now
    history.user_id = user_id
    history.result = "success"
    db.add(history)

    # MFA 활성화 확인 — 활성화된 경우 임시 쿠키만 발급하고 TOTP 검증 요청
    mfa_record = db.query(UserMfa).filter(
        UserMfa.user_id == user_id, UserMfa.is_active == True
    ).first()
    if mfa_record:
        db.commit()
        _record_audit(db, user_id, "LOGIN_MFA_REQUIRED", "200", request)
        mfa_pending_token = create_access_token(
            {"sub": str(user_id), "mfa_pending": True},
            expires_in=MFA_PENDING_EXPIRE_SECONDS,
        )
        resp = JSONResponse({"mfa_required": True})
        resp.set_cookie(
            key="mfa_pending",
            value=mfa_pending_token,
            httponly=True,
            secure=COOKIE_SECURE,
            samesite="strict",
            max_age=MFA_PENDING_EXPIRE_SECONDS,
            path="/",
        )
        return resp

    access_token  = create_access_token(token_payload, ACCESS_TOKEN_EXPIRE_SECONDS)
    refresh_token = generate_refresh_token()

    db.add(SessionModel(
        user_id            = user_id,
        refresh_token_hash = sha256_hex(refresh_token),
        user_agent         = request.headers.get("user-agent"),
        ip_address         = get_client_ip(request),
        expires_at         = now + timedelta(hours=REFRESH_TOKEN_EXPIRE_HOURS),
    ))
    db.commit()  # user 업데이트 + 로그인 이력 + 세션 토큰을 role_admin 상태에서 한 번에 커밋

    _record_audit(db, user_id, "LOGIN", "200", request)  # 감사 로그는 주요 작업 완료 후

    access_token_expires_at = (
        now + timedelta(seconds=ACCESS_TOKEN_EXPIRE_SECONDS)
    ).isoformat()

    # 온프레미스 전용으로 변경 — by 김다정, 2026-06-14
    # 크로스 도메인 전달 불필요: 응답 body에서 access_token 제거
    response = JSONResponse({
        "token_type":              "bearer",
        "expires_in":              ACCESS_TOKEN_EXPIRE_SECONDS,
        "access_token_expires_at": access_token_expires_at,
    })
    _set_auth_cookies(response, access_token, refresh_token)
    return response


def _set_auth_cookies(response: Response, access_token: str, refresh_token: str) -> None:
    # 온프레미스 전용 — by 김다정, 2026-06-14
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
        path="/api/staff/auth/refresh",
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
    _record_audit(db, user.user_id, "TOKEN_REFRESH", "200", request)

    new_expires_at = (
        now + timedelta(seconds=ACCESS_TOKEN_EXPIRE_SECONDS)
    ).isoformat()

    response = JSONResponse({
        "token_type":              "bearer",
        "expires_in":              ACCESS_TOKEN_EXPIRE_SECONDS,
        "access_token_expires_at": new_expires_at,
    })
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
            _record_audit(db, session.user_id, "LOGOUT", "204", request)
            db.commit()

    response.delete_cookie(key="access_token",  path="/")
    response.delete_cookie(key="refresh_token", path="/api/staff/auth/refresh")


@router.get("/me")
def me(
    current_user: dict     = Depends(get_current_user),
    db:           DbSession = Depends(get_auth_db),  # get_db → get_auth_db: users 테이블은 role_doctor/nurse가 접근 불가
):
    user = db.query(User).filter(User.user_id == current_user["sub"]).first()
    if not user:
        raise HTTPException(status_code=401, detail="사용자를 찾을 수 없습니다.")

    policy = get_password_policy(db)
    now    = datetime.now(timezone.utc)
    password_expired = (
        (now - user.password_changed_at).days >= policy.expire_days
        if user.password_changed_at else False
    )

    mfa_record = db.query(UserMfa).filter(
        UserMfa.user_id == user.user_id, UserMfa.is_active == True
    ).first()

    result = {
        "user_id":              str(user.user_id),
        "member_number":        user.member_number,
        "role":                 user.role_ref.role_code,
        "password_expired":     password_expired,
        "must_change_password": user.must_change_password,
        "password_expire_days": policy.expire_days,
        "mfa_enabled":          mfa_record is not None,
    }
    if user.patient_id:
        result["patient_id_hash"] = str(user.patient_id)
    if user.doctor_id:
        if _DB_MODE == "onprem":
            doctor = db.query(OnpremDoctor).filter(OnpremDoctor.doctor_id == user.doctor_id).first()
            if doctor:
                result["department_code"] = doctor.department_code
                result["doctor_name"]     = doctor.doctor_name
                dept = db.query(OnpremDepartment).filter(
                    OnpremDepartment.department_code == doctor.department_code
                ).first()
                result["department_name"] = dept.department_name if dept else doctor.department_code
        else:
            doctor = db.query(SyncDoctor).filter(SyncDoctor.doctor_id == user.doctor_id).first()
            if doctor:
                result["department_code"] = doctor.department_code
                result["doctor_name"]     = doctor.doctor_name
                dept = db.query(SyncDepartment).filter(
                    SyncDepartment.department_code == doctor.department_code
                ).first()
                result["department_name"] = dept.department_name if dept else doctor.department_code
    return result


@router.post("/change-password", status_code=204)
def change_password(
    body:         ChangePasswordRequest,
    request:      Request,
    response:     Response,
    current_user: dict      = Depends(get_current_user),
    db:           DbSession = Depends(get_auth_db),  # get_db → get_auth_db
):
    user = db.query(User).filter(User.user_id == current_user["sub"]).first()

    if not verify_password(body.old_password, user.password_hash):
        raise HTTPException(status_code=400, detail="현재 비밀번호가 올바르지 않습니다.")

    pw_error = validate_password(body.new_password)
    if pw_error:
        raise HTTPException(status_code=400, detail=pw_error)

    user.password_hash        = hash_password(body.new_password)
    user.password_changed_at  = datetime.now(timezone.utc)
    user.must_change_password = False

    # 비밀번호 변경 시 기존 세션 전체 폐기 (탈취된 토큰 무력화)
    db.query(SessionModel).filter(
        SessionModel.user_id    == user.user_id,
        SessionModel.is_revoked == False,
    ).update({"is_revoked": True})

    _record_audit(db, user.user_id, "PASSWORD_CHANGE", "204", request)
    db.commit()

    response.delete_cookie(key="access_token",  path="/")
    response.delete_cookie(key="refresh_token", path="/api/staff/auth/refresh")


# ── MFA 엔드포인트 ───────────────────────────────────────────────

@router.post("/mfa/verify")
def mfa_verify(
    body:    MfaVerifyRequest,
    request: Request,
    db:      DbSession = Depends(get_auth_db),
    _:       str       = Depends(verify_api_key),
):
    """로그인 중 TOTP 코드 검증 → 성공 시 access_token / refresh_token 발급."""
    mfa_pending_token = request.cookies.get("mfa_pending")
    if not mfa_pending_token:
        raise HTTPException(status_code=401, detail="MFA 세션이 없습니다. 다시 로그인하세요.")

    from core.security import decode_access_token
    try:
        payload = decode_access_token(mfa_pending_token)
    except HTTPException:
        raise HTTPException(status_code=401, detail="MFA 세션이 만료되었습니다. 다시 로그인하세요.")

    if not payload.get("mfa_pending"):
        raise HTTPException(status_code=401, detail="유효하지 않은 MFA 세션입니다.")

    user = db.query(User).filter(User.user_id == payload["sub"]).first()
    if not user:
        raise HTTPException(status_code=401, detail="사용자를 찾을 수 없습니다.")

    mfa_record = db.query(UserMfa).filter(
        UserMfa.user_id == user.user_id, UserMfa.is_active == True
    ).first()
    if not mfa_record:
        raise HTTPException(status_code=401, detail="MFA 설정이 없습니다.")

    try:
        secret = _decrypt_totp_secret(mfa_record.secret)
    except Exception:
        raise HTTPException(status_code=500, detail="MFA 복호화 오류가 발생했습니다.")

    if not pyotp.TOTP(secret).verify(body.code, valid_window=1):
        _record_audit(db, user.user_id, "MFA_FAIL", "401", request)
        raise HTTPException(status_code=401, detail="인증 코드가 올바르지 않습니다.")

    now           = datetime.now(timezone.utc)
    token_payload = _build_token_payload(user)
    access_token  = create_access_token(token_payload, ACCESS_TOKEN_EXPIRE_SECONDS)
    refresh_token = generate_refresh_token()

    db.add(SessionModel(
        user_id            = user.user_id,
        refresh_token_hash = sha256_hex(refresh_token),
        user_agent         = request.headers.get("user-agent"),
        ip_address         = get_client_ip(request),
        expires_at         = now + timedelta(hours=REFRESH_TOKEN_EXPIRE_HOURS),
    ))
    db.commit()
    _record_audit(db, user.user_id, "LOGIN_MFA_SUCCESS", "200", request)

    response = JSONResponse({
        "token_type":              "bearer",
        "expires_in":              ACCESS_TOKEN_EXPIRE_SECONDS,
        "access_token_expires_at": (now + timedelta(seconds=ACCESS_TOKEN_EXPIRE_SECONDS)).isoformat(),
    })
    response.delete_cookie(key="mfa_pending", path="/")
    _set_auth_cookies(response, access_token, refresh_token)
    return response


@router.post("/mfa/setup", status_code=201)
def mfa_setup(
    request:      Request,
    current_user: dict     = Depends(get_current_user),
    db:           DbSession = Depends(get_auth_db),
    _:            str       = Depends(verify_api_key),
):
    """MFA 등록 시작 — 시크릿 생성 후 QR코드 URL 반환."""
    user = db.query(User).filter(User.user_id == current_user["sub"]).first()
    if not user:
        raise HTTPException(status_code=401, detail="사용자를 찾을 수 없습니다.")

    secret           = pyotp.random_base32()
    encrypted_secret = _encrypt_totp_secret(secret)

    existing = db.query(UserMfa).filter(UserMfa.user_id == user.user_id).first()
    if existing:
        existing.secret      = encrypted_secret
        existing.is_active   = False
        existing.verified_at = None
    else:
        db.add(UserMfa(
            user_id   = user.user_id,
            mfa_type  = "totp",
            secret    = encrypted_secret,
            is_active = False,
        ))
    db.commit()

    qr_url = pyotp.TOTP(secret).provisioning_uri(
        name        = user.member_number or str(user.user_id),
        issuer_name = "병원EMR",
    )

    import qrcode, io, base64
    img = qrcode.make(qr_url)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_image = "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()

    return {"qr_url": qr_url, "qr_image": qr_image}


@router.post("/mfa/setup/verify", status_code=204)
def mfa_setup_verify(
    body:         MfaSetupVerifyRequest,
    request:      Request,
    current_user: dict     = Depends(get_current_user),
    db:           DbSession = Depends(get_auth_db),
    _:            str       = Depends(verify_api_key),
):
    """QR 스캔 후 첫 코드 검증 → is_active=True 저장."""
    user = db.query(User).filter(User.user_id == current_user["sub"]).first()
    if not user:
        raise HTTPException(status_code=401, detail="사용자를 찾을 수 없습니다.")

    mfa_record = db.query(UserMfa).filter(
        UserMfa.user_id == user.user_id, UserMfa.is_active == False
    ).first()
    if not mfa_record:
        raise HTTPException(status_code=400, detail="MFA 등록 정보가 없습니다. 먼저 /auth/mfa/setup을 호출하세요.")

    try:
        secret = _decrypt_totp_secret(mfa_record.secret)
    except Exception:
        raise HTTPException(status_code=500, detail="MFA 복호화 오류가 발생했습니다.")

    if not pyotp.TOTP(secret).verify(body.code, valid_window=1):
        raise HTTPException(status_code=400, detail="인증 코드가 올바르지 않습니다.")

    mfa_record.is_active   = True
    mfa_record.verified_at = datetime.now(timezone.utc)
    db.commit()
    _record_audit(db, user.user_id, "MFA_SETUP_COMPLETE", "204", request)


_ROLE_MENUS = {
    "nurse": [
        {"menu_code": "NURSE_DASHBOARD",    "menu_name": "예약 현황",      "menu_url": "/nurse-dashboard.html",       "icon": "calendar-alt"},
        {"menu_code": "NURSE_APPT_NEW",     "menu_name": "수동 예약",       "menu_url": "/nurse-appointment-new.html", "icon": "plus-circle"},
        {"menu_code": "PATIENT_REGISTER",   "menu_name": "환자 등록",       "menu_url": "/patient-register.html",      "icon": "user-plus"},
        {"menu_code": "PATIENT_SEARCH",     "menu_name": "환자 검색",       "menu_url": "/patient-search.html",        "icon": "search"},
        {"menu_code": "WARD_STATUS",        "menu_name": "병동 현황",       "menu_url": "/ward-status.html",           "icon": "hospital"},
        {"menu_code": "ENCOUNTER_NEW",      "menu_name": "진료 등록",       "menu_url": "/encounter-new.html",         "icon": "notes-medical"},
        {"menu_code": "CHANGE_PW",          "menu_name": "비밀번호 변경",   "menu_url": "/change-password.html",       "icon": "key"},
        {"menu_code": "MFA_SETUP",          "menu_name": "2단계 인증 설정", "menu_url": "/mfa-setup.html",             "icon": "mobile-alt"},
    ],
    "doctor": [
        {"menu_code": "DOCTOR_SCHEDULE",    "menu_name": "오늘 진료",       "menu_url": "/doctor-schedule.html",       "icon": "stethoscope"},
        {"menu_code": "PATIENT_SEARCH",     "menu_name": "환자 검색",       "menu_url": "/patient-search.html",        "icon": "search"},
        {"menu_code": "MY_PATIENTS",        "menu_name": "내 환자 목록",    "menu_url": "/my-patients.html",           "icon": "user-injured"},
        {"menu_code": "ENCOUNTER_NEW",      "menu_name": "진료 기록",       "menu_url": "/encounter-new.html",         "icon": "notes-medical"},
        {"menu_code": "CHANGE_PW",          "menu_name": "비밀번호 변경",   "menu_url": "/change-password.html",       "icon": "key"},
        {"menu_code": "MFA_SETUP",          "menu_name": "2단계 인증 설정", "menu_url": "/mfa-setup.html",             "icon": "mobile-alt"},
    ],
    "admin": [
        {"menu_code": "ADMIN_DASHBOARD",    "menu_name": "운영 대시보드",   "menu_url": "/admin-dashboard.html",       "icon": "tachometer-alt"},
        {"menu_code": "ADMIN_USERS",        "menu_name": "사용자 관리",     "menu_url": "/admin-users.html",           "icon": "users"},
        {"menu_code": "ADMIN_ROLES",        "menu_name": "역할/권한 관리",  "menu_url": "/admin-roles.html",           "icon": "shield-alt"},
        {"menu_code": "ADMIN_POLICY",       "menu_name": "보안 정책",       "menu_url": "/admin-policy.html",          "icon": "lock"},
        {"menu_code": "ADMIN_LOGS",         "menu_name": "감사 로그",       "menu_url": "/admin-logs.html",            "icon": "clipboard-list"},
        {"menu_code": "ADMIN_LOGIN_HIST",   "menu_name": "로그인 이력",     "menu_url": "/admin-login-history.html",   "icon": "history"},
        {"menu_code": "CHANGE_PW",          "menu_name": "비밀번호 변경",   "menu_url": "/change-password.html",       "icon": "key"},
        {"menu_code": "MFA_SETUP",          "menu_name": "2단계 인증 설정", "menu_url": "/mfa-setup.html",             "icon": "mobile-alt"},
    ],
}


@router.get("/me/permissions")
def get_my_permissions(
    current_user: dict     = Depends(get_current_user),
    db:           DbSession = Depends(get_auth_db),  # get_db → get_auth_db
):
    """현재 로그인 사용자의 권한 목록 반환 (ISMS-P 2.5.4)."""
    user = db.query(User).filter(User.user_id == current_user["sub"]).first()
    if not user:
        raise HTTPException(status_code=401, detail="사용자를 찾을 수 없습니다.")

    from models.db import Permission, RolePermission
    perms = (
        db.query(Permission)
        .join(RolePermission, Permission.permission_id == RolePermission.permission_id)
        .filter(RolePermission.role_id == user.role_id)
        .all()
    )
    return [
        {
            "permission_code": p.permission_code,
            "permission_name": p.permission_name,
            "category":        p.category,
        }
        for p in perms
    ]


@router.get("/me/menus")
def get_menus(
    current_user: dict     = Depends(get_current_user),
    db:           DbSession = Depends(get_auth_db),  # get_db → get_auth_db
):
    """역할에 따른 메뉴 목록 반환. DB role_menus 우선, 없으면 기본값 사용."""
    user = db.query(User).filter(User.user_id == current_user["sub"]).first()
    if not user:
        raise HTTPException(status_code=401, detail="사용자를 찾을 수 없습니다.")

    role_code = user.role_ref.role_code

    db_menus = (
        db.query(Menu)
        .join(RoleMenu, Menu.menu_id == RoleMenu.menu_id)
        .join(Role, RoleMenu.role_id == Role.role_id)
        .filter(Role.role_code == role_code, Menu.is_active == True)
        .order_by(Menu.sort_order)
        .all()
    )

    if db_menus:
        return [
            {"menu_code": m.menu_code, "menu_name": m.menu_name, "menu_url": m.menu_url, "icon": "circle"}
            for m in db_menus
        ]

    return _ROLE_MENUS.get(role_code, [])


@router.get("/session-status")
def session_status(
    current_user: dict = Depends(get_current_user),
):
    """액세스 토큰 잔여 시간 반환. 프론트엔드 만료 경고 타이머용."""
    exp = current_user.get("exp")
    if not exp:
        return {"remaining_seconds": 0, "will_expire_soon": True, "expires_at": None}

    now_ts    = datetime.now(timezone.utc).timestamp()
    remaining = max(0, int(exp - now_ts))

    return {
        "remaining_seconds": remaining,
        "will_expire_soon":  remaining < 300,
        "expires_at":        datetime.fromtimestamp(exp, tz=timezone.utc).isoformat(),
    }

