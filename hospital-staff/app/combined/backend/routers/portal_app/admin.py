from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DbSession

from core.database import get_db
from core.security import get_current_user, hash_password, verify_api_key
from routers.portal_app.auth import validate_password
from models.db import User

router = APIRouter(prefix="/admin", tags=["admin"])

ALLOWED_ROLES = ("patient", "doctor", "nurse", "admin")


class CreateUserRequest(BaseModel):
    email:     EmailStr
    password:  str
    role:      str        # patient | doctor | nurse | admin
    doctor_id: str | None = None  # doctor/nurse 계정 시 sync_doctors.doctor_id


def require_admin(current_user: dict = Depends(get_current_user)) -> dict:
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="관리자 권한이 필요합니다.")
    return current_user


@router.post("/users", status_code=201)
def create_user(
    body:         CreateUserRequest,
    db:           DbSession = Depends(get_db),
    _:            str       = Depends(verify_api_key),
    current_user: dict      = Depends(require_admin),
):
    if body.role not in ALLOWED_ROLES:
        raise HTTPException(status_code=400, detail=f"role은 {ALLOWED_ROLES} 중 하나여야 합니다.")

    pw_error = validate_password(body.password)
    if pw_error:
        raise HTTPException(status_code=400, detail=pw_error)

    if db.query(User).filter(User.email == body.email).first():
        raise HTTPException(status_code=400, detail="이미 사용 중인 이메일입니다.")

    user = User(
        email         = body.email,
        password_hash = hash_password(body.password),
        role          = body.role,
        doctor_id     = body.doctor_id,
    )
    db.add(user)
    try:
        db.commit()
        db.refresh(user)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=400, detail="이미 계정이 존재합니다.")

    return {"user_id": str(user.user_id), "role": user.role}
