import os

# ── Vault 시크릿 로드 ─────────────────────────────────────────
# security.py 임포트 전에 실행해야 JWT_SECRET 등이 올바르게 설정됨.
# VAULT_ADDR 미설정 시 즉시 반환 (로컬 개발 환경 호환).
from core.vault_loader import load_vault_secrets
load_vault_secrets()
from core.logging_config import setup_logging
setup_logging()
from core.security import reload_jwt_secrets
reload_jwt_secrets()
# ──────────────────────────────────────────────────────────────

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from sqlalchemy import text
from sqlalchemy.orm import Session as DbSession
from fastapi import Depends

from core.database import Base, engine, get_db, start_cred_refresher
from core.middleware import AuditLogMiddleware, SessionExpiryMiddleware
from models import db as _models  # noqa: F401 — Base에 모델 등록

from routers.patient import auth as patient_auth, portal as patient_portal
from routers.staff import auth as staff_auth, portal as staff_portal, admin as staff_admin, emr as staff_emr, emr_doctor as staff_emr_doctor, emr_admissions as staff_emr_admissions
from routers.portal_app import auth as portal_auth, portal as portal_portal, admin as portal_admin

app = FastAPI(
    title="김이박 병원 통합 API",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
@app.on_event("startup")
def _start_vault_cred_refresher():
    start_cred_refresher()




app.add_middleware(SessionExpiryMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("ALLOWED_ORIGINS", "").split(","),
    allow_credentials=True,   # httponly 쿠키 전송 필수
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-API-Key"],
)
app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(AuditLogMiddleware)

_allowed_hosts = os.getenv("ALLOWED_HOSTS", "localhost,127.0.0.1").split(",")
app.add_middleware(TrustedHostMiddleware, allowed_hosts=_allowed_hosts)

# ── 환자 포털 (/patient/auth/, /patient/portal/) ────────────
app.include_router(patient_auth.router,   prefix="/patient")
app.include_router(patient_portal.router, prefix="/patient")

# ── 의료진 포털 (/staff/auth/, /staff/portal/, /staff/admin/, /staff/emr/) ──
app.include_router(staff_auth.router,   prefix="/staff")
app.include_router(staff_portal.router, prefix="/staff")
app.include_router(staff_admin.router,  prefix="/staff")
app.include_router(staff_emr_doctor.router,     prefix="/staff")  # ← 위로
app.include_router(staff_emr_admissions.router, prefix="/staff")
app.include_router(staff_emr.router,            prefix="/staff")

# ── 병원 포털 (/portal/auth/, /portal/portal/, /portal/admin/) ──
app.include_router(portal_auth.router,    prefix="/portal")
app.include_router(portal_portal.router,  prefix="/portal")
app.include_router(portal_admin.router,   prefix="/portal")


# 260612 박경수: health — 인증 없이 DB 핑만
@app.get("/health")
def health():
    from core.database import engine
    from sqlalchemy import text
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return {"status": "ok", "db": "ok"}
    except Exception as e:
        return {"status": "degraded", "db": f"error: {e}"}
