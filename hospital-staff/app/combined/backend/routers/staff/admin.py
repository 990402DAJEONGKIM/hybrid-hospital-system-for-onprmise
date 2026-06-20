import os
import uuid as _uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DbSession

from core.database import get_db, get_auth_db
from core.security import get_current_user, get_client_ip, hash_password, verify_api_key
from routers.staff.auth import validate_password
from models.db import (
    AuditLog, Appointment, AppointmentStatus, LoginHistory, Menu, Notification,
    OnpremDepartment, OnpremDoctor, PasswordPolicy, Permission, Role, RoleMenu, RolePermission,
    Session as SessionModel, SyncDoctor, User,
)

router = APIRouter(prefix="/admin", tags=["admin"])

ALLOWED_ROLES = ("patient", "doctor", "nurse", "admin")


# ── 스키마 ─────────────────────────────────────────────────────

class CreateUserRequest(BaseModel):
    role_code:     str
    password:      str
    email:         Optional[str] = None          # 직원·의사 필수
    member_number: Optional[str] = None          # 환자 필수
    doctor_id:     Optional[str] = None          # 의사 계정 시


class UpdateUserRequest(BaseModel):
    role_code:     Optional[str]  = None
    doctor_id:     Optional[str]  = None
    is_active:     Optional[bool] = None
    email:         Optional[str]  = None
    member_number: Optional[str]  = None


class LockUserRequest(BaseModel):
    lock:  bool
    hours: Optional[int] = None   # 잠금 시간 (기본 24h)


class ResetPasswordRequest(BaseModel):
    new_password: str


class RoleCreateRequest(BaseModel):
    role_code:   str
    role_name:   str
    description: Optional[str] = None


class RolePermissionsUpdate(BaseModel):
    permission_codes: list[str]


class RoleMenusUpdate(BaseModel):
    menu_codes: list[str]


class PasswordPolicyUpdate(BaseModel):
    min_length:        Optional[int]  = None
    require_uppercase: Optional[bool] = None
    require_lowercase: Optional[bool] = None
    require_digit:     Optional[bool] = None
    require_special:   Optional[bool] = None
    expire_days:       Optional[int]  = None
    max_failed_logins: Optional[int]  = None
    lockout_minutes:   Optional[int]  = None


# ── 의존성 ─────────────────────────────────────────────────────

def require_admin(current_user: dict = Depends(get_current_user)) -> dict:
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="관리자 권한이 필요합니다.")
    return current_user


# 260612 박경수: 직접 INSERT → 공통 record_audit(log_audit 경유)
def _audit(db: DbSession, admin_id: str, action: str, target_id=None, request: Request = None):
    from core.security import record_audit
    record_audit(
        db,
        action_type = action,
        result_code = "200",
        user_id     = admin_id,
        target_id   = target_id,
        source_ip   = get_client_ip(request) if request else None,
    )
    db.commit()


# ── 진료과 목록 / 다음 직원번호 채번 ──────────────────────────

@router.get("/departments")
def list_departments_admin(
    db:           DbSession = Depends(get_db),
    _:            str       = Depends(verify_api_key),
    current_user: dict      = Depends(require_admin),
):
    """진료과 목록 (계정 생성 시 의사 부서 선택용)."""
    depts = (
        db.query(OnpremDepartment)
        .filter(OnpremDepartment.is_active == True)
        .order_by(OnpremDepartment.department_code)
        .all()
    )
    return [
        {"department_code": d.department_code, "department_name": d.department_name}
        for d in depts
    ]


@router.get("/doctors")
def list_doctors_admin(
    db:           DbSession = Depends(get_db),
    _:            str       = Depends(verify_api_key),
    current_user: dict      = Depends(require_admin),
):
    """의사 목록 (계정 생성·수정 시 doctor_id 선택용)."""
    if os.getenv("DB_MODE", "cloud") == "onprem":
        doctors = (
            db.query(OnpremDoctor)
            .filter(OnpremDoctor.is_active == True)
            .order_by(OnpremDoctor.doctor_name)
            .all()
        )
    else:
        doctors = (
            db.query(SyncDoctor)
            .filter(SyncDoctor.is_active == True)
            .order_by(SyncDoctor.doctor_name)
            .all()
        )
    return [
        {"doctor_id": str(d.doctor_id), "doctor_name": d.doctor_name,
         "department_code": d.department_code}
        for d in doctors
    ]


@router.get("/next-member-number")
def next_member_number(
    role_code: str           = Query(...),
    dept_code: Optional[str] = Query(default=None),
    db:        DbSession     = Depends(get_auth_db),
    _:         str           = Depends(verify_api_key),
    current_user: dict       = Depends(require_admin),
):
    """다음 직원번호 자동 채번.
    doctor → dr-{DEPT}-{N+1}
    nurse  → nurse-{N+1}
    admin  → admin-{N+1}
    """
    if role_code == "doctor":
        if not dept_code:
            raise HTTPException(status_code=400, detail="의사 계정은 dept_code가 필요합니다.")
        prefix = f"dr-{dept_code.upper()}-"
    elif role_code == "nurse":
        prefix = "nurse-"
    elif role_code == "admin":
        prefix = "admin-"
    else:
        raise HTTPException(status_code=400, detail="doctor / nurse / admin 만 지원합니다.")

    rows = (
        db.query(User.member_number)
        .filter(User.member_number.like(f"{prefix}%"))
        .all()
    )
    max_n = 0
    for (mn,) in rows:
        suffix = mn[len(prefix):]
        if suffix.isdigit():
            max_n = max(max_n, int(suffix))

    return {"member_number": f"{prefix}{max_n + 1}"}


# ── 사용자 관리 (SFR-030) ─────────────────────────────────────

@router.post("/users", status_code=201)
def create_user(
    body:         CreateUserRequest,
    request:      Request,
    db:           DbSession = Depends(get_auth_db),
    _:            str       = Depends(verify_api_key),
    current_user: dict      = Depends(require_admin),
):
    """계정 생성 — 직원(email 필수) / 환자(member_number 필수). SFR-030."""
    if body.role_code not in ALLOWED_ROLES:
        raise HTTPException(status_code=400, detail=f"role_code는 {ALLOWED_ROLES} 중 하나여야 합니다.")

    pw_error = validate_password(body.password)
    if pw_error:
        raise HTTPException(status_code=400, detail=pw_error)

    role = db.query(Role).filter(Role.role_code == body.role_code, Role.is_active == True).first()
    if not role:
        raise HTTPException(status_code=400, detail="유효하지 않은 역할 코드입니다.")

    is_patient = body.role_code == "patient"

    if is_patient:
        if not body.member_number:
            raise HTTPException(status_code=400, detail="환자 계정은 member_number가 필수입니다.")
        if db.query(User).filter(User.member_number == body.member_number).first():
            raise HTTPException(status_code=400, detail="이미 사용 중인 회원번호입니다.")
    else:
        if not body.member_number:
            raise HTTPException(status_code=400, detail="직원 계정은 직원번호(member_number)가 필수입니다.")
        if db.query(User).filter(User.member_number == body.member_number).first():
            raise HTTPException(status_code=400, detail="이미 사용 중인 직원번호입니다.")
        if body.email and db.query(User).filter(User.email == body.email).first():
            raise HTTPException(status_code=400, detail="이미 사용 중인 이메일입니다.")

    doctor_uuid = None
    if body.doctor_id:
        try:
            doctor_uuid = _uuid.UUID(body.doctor_id)
        except ValueError:
            raise HTTPException(status_code=422, detail="유효하지 않은 doctor_id입니다.")

    user = User(
        email                = body.email if not is_patient else None,
        member_number        = body.member_number,
        password_hash        = hash_password(body.password),
        role_id              = role.role_id,
        doctor_id            = doctor_uuid,
        is_active            = True,
        must_change_password = True,
    )
    db.add(user)
    try:
        db.commit()
        db.refresh(user)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=400, detail="이미 계정이 존재합니다.")

    _audit(db, current_user["sub"], "USER_CREATE", user.user_id, request)
    return {"user_id": str(user.user_id), "role_code": role.role_code}


@router.get("/users")
def list_users(
    db:           DbSession = Depends(get_auth_db),
    _:            str       = Depends(verify_api_key),
    current_user: dict      = Depends(require_admin),
):
    """전체 사용자 목록 조회."""
    now   = datetime.now(timezone.utc)
    users = db.query(User).order_by(User.created_at.desc()).all()
    return [
        {
            "user_id":       str(u.user_id),
            "email":         u.email,
            "member_number": u.member_number,
            "role_code":     u.role_ref.role_code if u.role_ref else None,
            "role_name":     u.role_ref.role_name if u.role_ref else None,
            "is_active":     u.is_active,
            "is_locked":     bool(u.locked_until and u.locked_until > now),
            "locked_until":  u.locked_until.isoformat() if u.locked_until else None,
            "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None,
            "created_at":    u.created_at.isoformat() if u.created_at else None,
        }
        for u in users
    ]


@router.patch("/users/{user_id}")
def update_user(
    user_id:      str,
    body:         UpdateUserRequest,
    request:      Request,
    db:           DbSession = Depends(get_auth_db),
    _:            str       = Depends(verify_api_key),
    current_user: dict      = Depends(require_admin),
):
    """역할·이메일·회원번호·활성 상태 수정 (비밀번호 제외). SFR-030."""
    try:
        uid = _uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="유효하지 않은 사용자 ID입니다.")
    if str(uid) == current_user["sub"]:
        raise HTTPException(status_code=400, detail="자기 자신의 계정은 변경할 수 없습니다.")

    user = db.query(User).filter(User.user_id == uid).first()
    if not user:
        raise HTTPException(status_code=404, detail="사용자를 찾을 수 없습니다.")

    if body.role_code is not None:
        role = db.query(Role).filter(Role.role_code == body.role_code, Role.is_active == True).first()
        if not role:
            raise HTTPException(status_code=400, detail="유효하지 않은 역할 코드입니다.")
        user.role_id = role.role_id
    if body.doctor_id is not None:
        try:
            user.doctor_id = _uuid.UUID(body.doctor_id) if body.doctor_id else None
        except ValueError:
            raise HTTPException(status_code=422, detail="유효하지 않은 doctor_id입니다.")
    if body.email is not None:
        user.email = body.email
    if body.member_number is not None:
        user.member_number = body.member_number
    if body.is_active is not None:
        user.is_active = body.is_active

    user.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(user)
    _audit(db, current_user["sub"], "USER_UPDATE", user.user_id, request)
    return {"user_id": str(user.user_id), "role_code": user.role_ref.role_code, "is_active": user.is_active}


@router.patch("/users/{user_id}/lock")
def lock_user(
    user_id:      str,
    body:         LockUserRequest,
    request:      Request,
    db:           DbSession = Depends(get_auth_db),
    _:            str       = Depends(verify_api_key),
    current_user: dict      = Depends(require_admin),
):
    """계정 잠금(locked_until 설정) / 잠금 해제(locked_until=null). SFR-030."""
    try:
        uid = _uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="유효하지 않은 사용자 ID입니다.")
    if str(uid) == current_user["sub"]:
        raise HTTPException(status_code=400, detail="자기 자신의 계정은 변경할 수 없습니다.")

    user = db.query(User).filter(User.user_id == uid).first()
    if not user:
        raise HTTPException(status_code=404, detail="사용자를 찾을 수 없습니다.")

    now = datetime.now(timezone.utc)
    if body.lock:
        hours            = body.hours or 24
        user.locked_until = now + timedelta(hours=hours)
    else:
        user.locked_until     = None
        user.failed_login_cnt = 0

    user.updated_at = now
    db.commit()
    db.refresh(user)
    _audit(db, current_user["sub"], "USER_LOCK", user.user_id, request)
    return {
        "user_id":     str(user.user_id),
        "is_locked":   bool(user.locked_until and user.locked_until > now),
        "locked_until": user.locked_until.isoformat() if user.locked_until else None,
    }


@router.delete("/users/{user_id}", status_code=200)
def delete_user(
    user_id:      str,
    request:      Request,
    db:           DbSession = Depends(get_auth_db),
    _:            str       = Depends(verify_api_key),
    current_user: dict      = Depends(require_admin),
):
    """계정 비활성화(is_active=false) + 활성 세션 즉시 폐기. SFR-030."""
    try:
        uid = _uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="유효하지 않은 사용자 ID입니다.")
    if str(uid) == current_user["sub"]:
        raise HTTPException(status_code=400, detail="자기 자신의 계정은 삭제할 수 없습니다.")

    user = db.query(User).filter(User.user_id == uid).first()
    if not user:
        raise HTTPException(status_code=404, detail="사용자를 찾을 수 없습니다.")

    # 소프트 삭제
    user.is_active   = False
    user.updated_at  = datetime.now(timezone.utc)

    # 활성 세션 즉시 폐기
    db.query(SessionModel).filter(
        SessionModel.user_id    == uid,
        SessionModel.is_revoked == False,
    ).update({"is_revoked": True})

    db.commit()
    _audit(db, current_user["sub"], "USER_DELETE", user.user_id, request)
    return {"user_id": str(user.user_id), "is_active": False}


@router.post("/users/{user_id}/reset-password")
def reset_password(
    user_id:      str,
    body:         ResetPasswordRequest,
    request:      Request,
    db:           DbSession = Depends(get_auth_db),
    _:            str       = Depends(verify_api_key),
    current_user: dict      = Depends(require_admin),
):
    """임시 비밀번호 발급 — must_change_password=true 강제. SFR-030."""
    try:
        uid = _uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="유효하지 않은 사용자 ID입니다.")

    pw_error = validate_password(body.new_password)
    if pw_error:
        raise HTTPException(status_code=400, detail=pw_error)

    user = db.query(User).filter(User.user_id == uid).first()
    if not user:
        raise HTTPException(status_code=404, detail="사용자를 찾을 수 없습니다.")

    user.password_hash        = hash_password(body.new_password)
    user.must_change_password = True
    user.password_changed_at  = datetime.now(timezone.utc)
    user.updated_at           = datetime.now(timezone.utc)

    # 기존 세션 폐기 (다음 로그인 시 비밀번호 변경 강제)
    db.query(SessionModel).filter(
        SessionModel.user_id    == uid,
        SessionModel.is_revoked == False,
    ).update({"is_revoked": True})

    db.commit()
    _audit(db, current_user["sub"], "USER_RESET_PW", user.user_id, request)
    return {"user_id": str(user.user_id), "must_change_password": True}


# ── 감사 로그 ──────────────────────────────────────────────────

@router.get("/audit-logs")
def list_audit_logs(
    action_type:  Optional[str] = Query(default=None),
    limit:        int           = Query(default=100, le=500),
    db:           DbSession     = Depends(get_db),
    _:            str           = Depends(verify_api_key),
    current_user: dict          = Depends(require_admin),
):
    query = db.query(AuditLog)
    if action_type:
        query = query.filter(AuditLog.action_type == action_type)
    logs = query.order_by(AuditLog.event_at.desc()).limit(limit).all()
    return [
        {
            "audit_log_id":    str(log.audit_log_id),
            "user_id":         str(log.user_id) if log.user_id else None,
            "action_type":     log.action_type,
            "target_table":    log.target_table,
            "patient_id_hash": log.patient_id_hash,
            "source_ip":       str(log.source_ip) if log.source_ip else None,
            "result_code":     log.result_code,
            "event_at":        log.event_at.isoformat() if log.event_at else None,
        }
        for log in logs
    ]


# ── 비밀번호 정책 (SFR-032) ────────────────────────────────────

@router.get("/password-policy")
def get_password_policy_endpoint(
    db:           DbSession = Depends(get_db),
    _:            str       = Depends(verify_api_key),
    current_user: dict      = Depends(require_admin),
):
    from core.security import get_password_policy
    policy = get_password_policy(db)
    return {
        "min_length":        policy.min_length,
        "require_uppercase": policy.require_uppercase,
        "require_lowercase": policy.require_lowercase,
        "require_digit":     policy.require_digit,
        "require_special":   policy.require_special,
        "expire_days":       policy.expire_days,
        "max_failed_logins": policy.max_failed_logins,
        "lockout_minutes":   policy.lockout_minutes,
        "updated_at":        policy.updated_at.isoformat() if policy.updated_at else None,
    }


@router.patch("/password-policy")
def update_password_policy(
    body:         PasswordPolicyUpdate,
    request:      Request,
    db:           DbSession = Depends(get_db),
    _:            str       = Depends(verify_api_key),
    current_user: dict      = Depends(require_admin),
):
    """보안 정책 업데이트 — 변경자·변경 일시 기록 + 감사 로그. SFR-032."""
    policy = db.query(PasswordPolicy).first()
    if not policy:
        policy = PasswordPolicy()
        db.add(policy)

    for field, value in body.model_dump(exclude_none=True).items():
        setattr(policy, field, value)
    policy.updated_at = datetime.now(timezone.utc)
    policy.updated_by = _uuid.UUID(current_user["sub"])

    db.commit()
    db.refresh(policy)
    _audit(db, current_user["sub"], "POLICY_UPDATE", None, request)
    return {"message": "보안 정책이 업데이트되었습니다."}


# ── 역할 / 권한 관리 (SFR-031) ────────────────────────────────

@router.get("/roles")
def list_roles(
    db:           DbSession = Depends(get_db),
    _:            str       = Depends(verify_api_key),
    current_user: dict      = Depends(require_admin),
):
    roles = db.query(Role).order_by(Role.role_id).all()
    return [
        {
            "role_id":     r.role_id,
            "role_code":   r.role_code,
            "role_name":   r.role_name,
            "description": r.description,
            "is_active":   r.is_active,
            "permissions": [
                {"permission_code": rp.permission.permission_code,
                 "permission_name": rp.permission.permission_name,
                 "category":        rp.permission.category}
                for rp in r.role_permissions
            ],
            "menus": [
                {"menu_code": rm.menu.menu_code,
                 "menu_name": rm.menu.menu_name,
                 "menu_url":  rm.menu.menu_url}
                for rm in r.role_menus
            ],
        }
        for r in roles
    ]


@router.post("/roles", status_code=201)
def create_role(
    body:         RoleCreateRequest,
    request:      Request,
    db:           DbSession = Depends(get_db),
    _:            str       = Depends(verify_api_key),
    current_user: dict      = Depends(require_admin),
):
    if db.query(Role).filter(Role.role_code == body.role_code).first():
        raise HTTPException(status_code=400, detail="이미 사용 중인 역할 코드입니다.")
    role = Role(role_code=body.role_code, role_name=body.role_name, description=body.description)
    db.add(role)
    db.commit()
    db.refresh(role)
    _audit(db, current_user["sub"], "ROLE_UPDATE", None, request)
    return {"role_id": role.role_id, "role_code": role.role_code}


@router.put("/roles/{role_id}/permissions")
def set_role_permissions(
    role_id:      int,
    body:         RolePermissionsUpdate,
    request:      Request,
    db:           DbSession = Depends(get_db),
    _:            str       = Depends(verify_api_key),
    current_user: dict      = Depends(require_admin),
):
    role = db.query(Role).filter(Role.role_id == role_id).first()
    if not role:
        raise HTTPException(status_code=404, detail="역할을 찾을 수 없습니다.")
    perm_ids = []
    for code in body.permission_codes:
        perm = db.query(Permission).filter(Permission.permission_code == code).first()
        if not perm:
            raise HTTPException(status_code=400, detail=f"권한 코드 '{code}'를 찾을 수 없습니다.")
        perm_ids.append(perm.permission_id)
    from sqlalchemy import text as _text
    db.execute(_text("SELECT admin_set_role_permissions(:role_id, :perm_ids)"),
               {"role_id": role_id, "perm_ids": perm_ids})
    db.commit()
    _audit(db, current_user["sub"], "PERMISSION_UPDATE", None, request)
    return {"message": f"역할 '{role.role_name}'의 권한이 업데이트되었습니다."}


@router.get("/permissions")
def list_permissions(
    db:           DbSession = Depends(get_db),
    _:            str       = Depends(verify_api_key),
    current_user: dict      = Depends(require_admin),
):
    perms = db.query(Permission).order_by(Permission.category, Permission.permission_id).all()
    return [
        {"permission_id":   p.permission_id,
         "permission_code": p.permission_code,
         "permission_name": p.permission_name,
         "category":        p.category}
        for p in perms
    ]


@router.get("/menus")
def list_menus(
    db:           DbSession = Depends(get_db),
    _:            str       = Depends(verify_api_key),
    current_user: dict      = Depends(require_admin),
):
    menus = db.query(Menu).filter(Menu.is_active == True).order_by(Menu.sort_order, Menu.menu_id).all()
    return [
        {"menu_id":   m.menu_id, "menu_code": m.menu_code,
         "menu_name": m.menu_name, "menu_url":  m.menu_url}
        for m in menus
    ]


@router.patch("/roles/{role_id}/menus")
def set_role_menus(
    role_id:      int,
    body:         RoleMenusUpdate,
    request:      Request,
    db:           DbSession = Depends(get_db),
    _:            str       = Depends(verify_api_key),
    current_user: dict      = Depends(require_admin),
):
    role = db.query(Role).filter(Role.role_id == role_id).first()
    if not role:
        raise HTTPException(status_code=404, detail="역할을 찾을 수 없습니다.")
    menu_ids = []
    for code in body.menu_codes:
        menu = db.query(Menu).filter(Menu.menu_code == code).first()
        if not menu:
            raise HTTPException(status_code=400, detail=f"메뉴 코드 '{code}'를 찾을 수 없습니다.")
        menu_ids.append(menu.menu_id)
    from sqlalchemy import text as _text
    db.execute(_text("SELECT admin_set_role_menus(:role_id, :menu_ids)"),
               {"role_id": role_id, "menu_ids": menu_ids})
    db.commit()
    _audit(db, current_user["sub"], "ROLE_UPDATE", None, request)
    return {"message": f"역할 '{role.role_name}'의 메뉴가 업데이트되었습니다."}


# ── 운영 대시보드 (SFR-029) ────────────────────────────────────

@router.get("/dashboard")
def get_dashboard(
    db:           DbSession = Depends(get_auth_db),
    _:            str       = Depends(verify_api_key),
    current_user: dict      = Depends(require_admin),
):
    """운영 대시보드 — 예약·보안 이벤트·미처리 알림·잠금 계정. SFR-029."""
    now   = datetime.now(timezone.utc)
    today = now.date()
    ago24 = now - timedelta(hours=24)

    # 예약 현황 (상태별)
    appt_rows = (
        db.query(AppointmentStatus.status_code, func.count(Appointment.appointment_id).label("cnt"))
        .join(AppointmentStatus, Appointment.status_id == AppointmentStatus.status_id)
        .filter(Appointment.appointment_date == today)
        .group_by(AppointmentStatus.status_code)
        .all()
    )
    appt_by_status = {row.status_code: row.cnt for row in appt_rows}
    appt_total = sum(appt_by_status.values())

    # 보안 이벤트 (24h, 타입별)
    SECURITY_TYPES = ["BREAK_GLASS", "USER_LOCK", "POLICY_UPDATE", "ACCOUNT_LOCKED", "USER_DELETE", "USER_CREATE"]
    sec_rows = (
        db.query(AuditLog.action_type, func.count(AuditLog.audit_log_id).label("cnt"))
        .filter(
            AuditLog.event_at >= ago24,
            AuditLog.action_type.in_(SECURITY_TYPES),
        )
        .group_by(AuditLog.action_type)
        .all()
    )
    security_events = {row.action_type: row.cnt for row in sec_rows}
    security_total  = sum(security_events.values())

    # 잠금 계정 수
    locked_accounts = db.query(func.count(User.user_id)).filter(
        User.locked_until > now, User.is_active == True,
    ).scalar() or 0

    # 미처리 알림 (status='pending')
    pending_notifications = db.query(func.count(Notification.notification_id)).filter(
        Notification.status == "pending",
    ).scalar() or 0

    # 최근 감사 이벤트 10건
    recent_events = db.query(AuditLog).order_by(AuditLog.event_at.desc()).limit(10).all()

    # 온프레미스 연결 상태
    onprem_status, onprem_detail = "unknown", ""
    try:
        import os, httpx
        base = os.getenv("ONPREM_API_URL", "").rstrip("/")
        if base:
            r = httpx.get(f"{base}/health", timeout=3.0)
            onprem_status = "ok" if r.status_code == 200 else "degraded"
        else:
            onprem_status = "not_configured"
    except Exception as e:
        onprem_status, onprem_detail = "error", str(e)[:80]

    return {
        "generated_at": now.isoformat(),
        "appointments": {
            "today_total": appt_total,
            "by_status":   appt_by_status,
        },
        "security": {
            "locked_accounts":  locked_accounts,
            "security_total_24h": security_total,
            "events_by_type":   security_events,
        },
        "pending_notifications": pending_notifications,
        "system": {
            "onprem_api":    onprem_status,
            "onprem_detail": onprem_detail,
            "combined_api":  "ok",
        },
        "recent_events": [
            {
                "action_type": e.action_type,
                "result_code": e.result_code,
                "event_at":    e.event_at.isoformat() if e.event_at else None,
            }
            for e in recent_events
        ],
    }
