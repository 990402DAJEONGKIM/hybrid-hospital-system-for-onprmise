import re
import uuid
import json      # 추가 260604 김강환 - Wazuh stdout JSON 직렬화용
import logging   # 추가 260604 김강환 - stdout 로거 생성용
import sys        # 추가 260604 김강환 - stdout 핸들러 출력 대상 지정용

from datetime import datetime, timezone
from fastapi import Request
from jose import JWTError, jwt
from starlette.middleware.base import BaseHTTPMiddleware

from core.database import SessionLocal
from core.security import JWT_ALGORITHM, JWT_SECRET, JWT_SECRET_PREVIOUS  # 260601 박경수 수정 - JWT_SECRET_PREVIOUS 추가

SESSION_WARN_SECONDS = 300  # 세션 만료 5분 전 경고

# ── 상수 ─────────────────────────────────────────────────────

SKIP_AUDIT_PATHS = {"/health", "/docs", "/redoc", "/openapi.json"}

UUID_PATTERN = re.compile(
    r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I
)


# ──────────────────────────────────────────────────────────────
# Wazuh stdout 로거 (추가 260604 김강환)
# 동작 흐름:
#   FastAPI stdout 출력 → Docker json-file 드라이버가 파일로 저장
#   → /var/lib/docker/containers/*/*-json.log
#   → ECS EC2의 Wazuh agent가 해당 파일을 읽어 Manager로 전송
# 별도 파일 저장 코드 불필요 — stdout 출력만 하면 Docker가 알아서 파일화함
# ──────────────────────────────────────────────────────────────
_wazuh_logger = logging.getLogger("wazuh.audit")
if not _wazuh_logger.handlers:                             # 추가 260605 김강환 - 핸들러 중복 방지 (hot reload 시 로그 중복 출력 방지)
    _wazuh_handler = logging.StreamHandler(sys.stdout)        # stdout으로 출력
    _wazuh_handler.setFormatter(logging.Formatter("%(message)s"))  # JSON만 출력 (로그레벨/시각 prefix 제거)
    _wazuh_logger.addHandler(_wazuh_handler)
    _wazuh_logger.setLevel(logging.INFO)
    _wazuh_logger.propagate = False    

def _emit_wazuh_log(action_type, result_code, user_id, source_ip, path, method, role=None):
    # UUID_PATTERN은 이 파일 상단에 이미 선언돼 있음 → 재사용
    # 예: /patients/a1b2...-... → /patients/{id}
    masked_path = UUID_PATTERN.sub("{id}", path)

    _wazuh_logger.info(json.dumps({
        "event_type":  "fastapi_audit",   # Wazuh 룰 필터용 식별자
        "action_type": action_type,        # LOGIN, CREATE_USER 등 행위 종류
        "result_code": result_code,        # HTTP 상태코드 (200/401 등)
        "user_id":     user_id,            # 직원 UUID (환자 정보 아님)
        "role":        role,               # admin/doctor/nurse
        "source_ip":   source_ip,          # 접속 IP (감사 추적용)
        "path":        masked_path,        # UUID 마스킹된 요청 경로
        "method":      method,             # GET/POST 등
        "timestamp":   datetime.now(timezone.utc).isoformat(),
    }, ensure_ascii=False))                # ensure_ascii=False: 한글 등 비ASCII 깨짐 방지
# (HTTP 메서드, 경로 패턴, action_type) — 순서 중요 (구체적인 경로 먼저)
# 260609 박경수 수정 - 실제 라우터 prefix 반영
ACTION_MAP = [
    # ── 스태프 인증 (/staff/auth/...) ────────────────────────────
    ("POST",   r"^/staff/auth/login$",                                    "LOGIN"),
    ("POST",   r"^/staff/auth/logout$",                                   "LOGOUT"),
    ("POST",   r"^/staff/auth/register$",                                 "REGISTER"),
    ("POST",   r"^/staff/auth/refresh$",                                  "TOKEN_REFRESH"),
    ("POST",   r"^/staff/auth/set-token$",                                "SET_TOKEN"),
    ("POST",   r"^/staff/auth/change-password$",                          "CHANGE_PASSWORD"),
    ("GET",    r"^/staff/auth/me/permissions$",                           "READ_PERMISSIONS"),
    ("GET",    r"^/staff/auth/me/menus$",                                 "READ_MENUS"),
    ("GET",    r"^/staff/auth/me$",                                       "READ_ME"),
    ("GET",    r"^/staff/auth/session-status$",                           "SESSION_STATUS"),
    # ── 스태프 포털 — 의사 (/staff/portal/doctor/...) ────────────
    ("GET",    r"^/staff/portal/doctor/schedule$",                        "VIEW_DOCTOR_SCHEDULE"),
    ("GET",    r"^/staff/portal/doctor/patients/[^/]+$",                  "READ_PATIENT_DETAIL"),
    ("GET",    r"^/staff/portal/doctor/patients$",                        "READ_PATIENTS"),
    # ── 스태프 포털 — 원무/공통 (/staff/portal/...) ───────────────
    ("GET",    r"^/staff/portal/appointments/today$",                     "VIEW_TODAY_APPOINTMENTS"),
    ("GET",    r"^/staff/portal/staff/appointments/[^/]+/history$",       "READ_APPOINTMENT_HISTORY"),
    ("GET",    r"^/staff/portal/staff/appointments/[^/]+$",               "READ_APPOINTMENT_DETAIL"),
    ("POST",   r"^/staff/portal/staff/appointments$",                     "CREATE_APPOINTMENT"),
    ("GET",    r"^/staff/portal/staff/appointments$",                     "VIEW_ALL_APPOINTMENTS"),
    ("PATCH",  r"^/staff/portal/staff/appointments/[^/]+/status$",        "UPDATE_APPOINTMENT_STATUS"),
    ("GET",    r"^/staff/portal/staff/wards$",                            "VIEW_WARD_STATUS"),
    ("PATCH",  r"^/staff/portal/staff/wards/[^/]+/discharge$",            "DISCHARGE_WARD"),
    ("GET",    r"^/staff/portal/staff/doctors$",                          "READ_DOCTORS"),
    ("GET",    r"^/staff/portal/staff/departments$",                      "READ_DEPARTMENTS"),
    ("GET",    r"^/staff/portal/nurse/patients/[^/]+/reception-info$",    "READ_RECEPTION_INFO"),
    ("GET",    r"^/staff/portal/nurse/dashboard$",                        "VIEW_NURSE_DASHBOARD"),
    ("GET",    r"^/staff/portal/appointment-types$",                      "READ_APPOINTMENT_TYPES"),
    # ── EMR 의사 전용 (/staff/emr/doctor/...) — emr보다 먼저 ─────
    ("GET",    r"^/staff/emr/doctor/patients/search$",                    "SEARCH_PATIENTS"),
    ("GET",    r"^/staff/emr/doctor/patients/[^/]+/emr$",                 "VIEW_EMR"),
    ("GET",    r"^/staff/emr/doctor/patients/[^/]+/encounters/latest$",   "READ_LATEST_ENCOUNTER"),
    ("GET",    r"^/staff/emr/doctor/patients$",                           "READ_PATIENTS"),
    ("POST",   r"^/staff/emr/doctor/encounters/[^/]+/notes$",             "CREATE_CLINICAL_NOTE"),
    ("POST",   r"^/staff/emr/doctor/encounters/[^/]+/diagnoses$",         "CREATE_DIAGNOSIS"),
    ("POST",   r"^/staff/emr/doctor/encounters$",                         "CREATE_ENCOUNTER"),
    ("PATCH",  r"^/staff/emr/doctor/encounters/[^/]+$",                   "UPDATE_ENCOUNTER"),
    ("POST",   r"^/staff/emr/doctor/patients/[^/]+/break-glass$",         "BREAK_GLASS"),
    # ── EMR 공통 (/staff/emr/...) ────────────────────────────────
    ("GET",    r"^/staff/emr/patients/by-hash/[^/]+$",                    "READ_PATIENT_BY_HASH"),
    ("GET",    r"^/staff/emr/patients/[^/]+/encounters$",                 "READ_ENCOUNTERS"),
    ("GET",    r"^/staff/emr/patients/[^/]+/diagnoses$",                  "READ_DIAGNOSES"),
    ("GET",    r"^/staff/emr/patients/[^/]+/clinical-notes$",             "READ_CLINICAL_NOTES"),
    ("GET",    r"^/staff/emr/patients/[^/]+/allergies$",                  "READ_ALLERGIES"),
    ("GET",    r"^/staff/emr/patients/[^/]+/surgery-histories$",          "READ_SURGERY_HISTORIES"),
    ("GET",    r"^/staff/emr/patients/[^/]+$",                            "READ_PATIENT_DETAIL"),
    ("GET",    r"^/staff/emr/patients$",                                  "READ_PATIENTS"),
    ("POST",   r"^/staff/emr/patients/[^/]+/diagnoses$",                  "CREATE_DIAGNOSIS"),
    ("POST",   r"^/staff/emr/patients/[^/]+/clinical-notes$",             "CREATE_CLINICAL_NOTE"),
    ("POST",   r"^/staff/emr/patients$",                                  "CREATE_PATIENT"),
    ("POST",   r"^/staff/emr/encounters$",                                "CREATE_ENCOUNTER"),
    ("PATCH",  r"^/staff/emr/encounters/[^/]+$",                          "UPDATE_ENCOUNTER"),
    ("GET",    r"^/staff/emr/departments$",                               "READ_DEPARTMENTS"),
    ("GET",    r"^/staff/emr/doctors$",                                   "READ_DOCTORS"),
    ("GET",    r"^/staff/emr/wards$",                                     "VIEW_WARD_STATUS"),
    ("POST",   r"^/staff/emr/ward-assignments$",                          "CREATE_WARD_ASSIGNMENT"),
    ("PATCH",  r"^/staff/emr/ward-assignments/[^/]+/discharge$",          "DISCHARGE_WARD"),
    ("POST",   r"^/staff/emr/appointments/[^/]+/reception$",              "RECEPTION_APPOINTMENT"),
    ("GET",    r"^/staff/emr/my/encounters$",                             "READ_MY_ENCOUNTERS"),
    ("POST",   r"^/staff/emr/nurse/patients/names-by-hashes$",            "READ_PATIENT_NAMES"),
    ("GET",    r"^/staff/emr/nurse/waiting-count$",                       "READ_WAITING_COUNT"),
    ("GET",    r"^/staff/emr/nurse/patients/search$",                     "SEARCH_PATIENTS"),
    ("GET",    r"^/staff/emr/nurse/patients/[^/]+/verify$",               "VERIFY_PATIENT"),
    ("GET",    r"^/staff/emr/nurse/patients/[^/]+/diagnoses$",            "READ_DIAGNOSES"),
    ("PATCH",  r"^/staff/emr/nurse/encounters/[^/]+/discharge$",          "DISCHARGE_ENCOUNTER"),
    ("POST",   r"^/staff/emr/nurse/encounters/checkin$",                  "CHECKIN"),
    ("POST",   r"^/staff/emr/nurse/encounters/admit$",                    "ADMIT_PATIENT"),
    # ── 관리자 (/staff/admin/...) ─────────────────────────────────
    ("POST",   r"^/staff/admin/users/[^/]+/reset-password$",              "RESET_PASSWORD"),
    ("PATCH",  r"^/staff/admin/users/[^/]+/lock$",                        "LOCK_USER"),
    ("PATCH",  r"^/staff/admin/users/[^/]+$",                             "UPDATE_USER"),
    ("DELETE", r"^/staff/admin/users/[^/]+$",                             "DELETE_USER"),
    ("POST",   r"^/staff/admin/users$",                                   "CREATE_USER"),
    ("GET",    r"^/staff/admin/users$",                                   "READ_USERS"),
    ("GET",    r"^/staff/admin/audit-logs$",                              "READ_AUDIT_LOGS"),
    ("GET",    r"^/staff/admin/password-policy$",                         "READ_PASSWORD_POLICY"),
    ("PATCH",  r"^/staff/admin/password-policy$",                         "UPDATE_PASSWORD_POLICY"),
    ("GET",    r"^/staff/admin/departments$",                             "READ_DEPARTMENTS"),
    ("GET",    r"^/staff/admin/next-member-number$",                      "READ_NEXT_MEMBER_NUMBER"),
    ("PUT",    r"^/staff/admin/roles/[^/]+/permissions$",                 "UPDATE_ROLE_PERMISSIONS"),
    ("PATCH",  r"^/staff/admin/roles/[^/]+/menus$",                       "UPDATE_ROLE_MENUS"),
    ("POST",   r"^/staff/admin/roles$",                                   "CREATE_ROLE"),
    ("GET",    r"^/staff/admin/roles$",                                   "READ_ROLES"),
    ("GET",    r"^/staff/admin/permissions$",                             "READ_PERMISSIONS"),
    ("GET",    r"^/staff/admin/menus$",                                   "READ_MENUS"),
    ("GET",    r"^/staff/admin/dashboard$",                               "VIEW_DASHBOARD"),
    # ── 환자 포털 인증 (/patient/auth/...) ───────────────────────
    ("POST",   r"^/patient/auth/login$",                                  "LOGIN"),
    ("POST",   r"^/patient/auth/logout$",                                 "LOGOUT"),
    ("POST",   r"^/patient/auth/register$",                               "REGISTER"),
    ("POST",   r"^/patient/auth/refresh$",                                "TOKEN_REFRESH"),
    ("POST",   r"^/patient/auth/change-password$",                        "CHANGE_PASSWORD"),
    ("GET",    r"^/patient/auth/me$",                                     "READ_ME"),
    ("GET",    r"^/patient/auth/session-status$",                         "SESSION_STATUS"),
    # ── 환자 포털 (/patient/portal/...) ──────────────────────────
    ("GET",    r"^/patient/portal/appointments/available-slots$",         "READ_AVAILABLE_SLOTS"),
    ("GET",    r"^/patient/portal/appointments/[^/]+/history$",           "READ_APPOINTMENT_HISTORY"),
    ("GET",    r"^/patient/portal/appointments/[^/]+$",                   "READ_APPOINTMENT"),
    ("POST",   r"^/patient/portal/appointments$",                         "CREATE_APPOINTMENT"),
    ("PATCH",  r"^/patient/portal/appointments/[^/]+$",                   "UPDATE_APPOINTMENT"),
    ("DELETE", r"^/patient/portal/appointments/[^/]+$",                   "DELETE_APPOINTMENT"),
    ("GET",    r"^/patient/portal/appointments$",                         "READ_APPOINTMENTS"),
    ("GET",    r"^/patient/portal/my-profile$",                           "READ_MY_PROFILE"),
    ("PATCH",  r"^/patient/portal/my-profile$",                           "UPDATE_MY_PROFILE"),
    ("GET",    r"^/patient/portal/recent-encounter$",                     "READ_RECENT_ENCOUNTER"),
    ("GET",    r"^/patient/portal/my-records$",                           "READ_MY_RECORDS"),
    ("GET",    r"^/patient/portal/encounters/[^/]+$",                     "READ_ENCOUNTER"),
    ("GET",    r"^/patient/portal/allergies$",                            "READ_ALLERGIES"),
    ("GET",    r"^/patient/portal/surgery-histories$",                    "READ_SURGERY_HISTORIES"),
    ("GET",    r"^/patient/portal/prescriptions$",                        "READ_PRESCRIPTIONS"),
    ("GET",    r"^/patient/portal/wards/availability$",                   "READ_WARD_AVAILABILITY"),
    ("GET",    r"^/patient/portal/appointment-types$",                    "READ_APPOINTMENT_TYPES"),
    ("GET",    r"^/patient/portal/departments$",                          "READ_DEPARTMENTS"),
    ("GET",    r"^/patient/portal/doctors$",                              "READ_DOCTORS"),
    # ── 병원 포털 인증 (/portal/auth/...) ────────────────────────
    ("POST",   r"^/portal/auth/login$",                                   "LOGIN"),
    ("POST",   r"^/portal/auth/logout$",                                  "LOGOUT"),
    ("POST",   r"^/portal/auth/register$",                                "REGISTER"),
    ("POST",   r"^/portal/auth/refresh$",                                 "TOKEN_REFRESH"),
    ("POST",   r"^/portal/auth/change-password$",                         "CHANGE_PASSWORD"),
    ("GET",    r"^/portal/auth/me$",                                      "READ_ME"),
    ("GET",    r"^/portal/auth/session-status$",                          "SESSION_STATUS"),
    # ── 병원 포털 (/portal/...) ───────────────────────────────────
    ("GET",    r"^/portal/appointments/[^/]+/history$",                   "READ_APPOINTMENT_HISTORY"),
    ("GET",    r"^/portal/appointments/[^/]+$",                           "READ_APPOINTMENT"),
    ("POST",   r"^/portal/appointments$",                                 "CREATE_APPOINTMENT"),
    ("PATCH",  r"^/portal/appointments/[^/]+$",                           "UPDATE_APPOINTMENT"),
    ("DELETE", r"^/portal/appointments/[^/]+$",                           "DELETE_APPOINTMENT"),
    ("GET",    r"^/portal/appointments$",                                 "READ_APPOINTMENTS"),
    ("GET",    r"^/portal/staff/appointments/[^/]+/history$",             "READ_APPOINTMENT_HISTORY"),
    ("GET",    r"^/portal/staff/appointments/[^/]+$",                     "READ_APPOINTMENT_DETAIL"),
    ("POST",   r"^/portal/staff/appointments$",                           "CREATE_APPOINTMENT"),
    ("PATCH",  r"^/portal/staff/appointments/[^/]+/status$",              "UPDATE_APPOINTMENT_STATUS"),
    ("GET",    r"^/portal/staff/appointments$",                           "VIEW_ALL_APPOINTMENTS"),
    ("GET",    r"^/portal/doctor/schedule$",                              "VIEW_DOCTOR_SCHEDULE"),
    ("GET",    r"^/portal/doctor/patients/[^/]+$",                        "READ_PATIENT_DETAIL"),
    ("GET",    r"^/portal/doctor/patients$",                              "READ_PATIENTS"),
    ("GET",    r"^/portal/doctors$",                                      "READ_DOCTORS"),
    ("GET",    r"^/portal/wards$",                                        "VIEW_WARD_STATUS"),
    ("GET",    r"^/portal/departments$",                                  "READ_DEPARTMENTS"),
    ("GET",    r"^/portal/appointment-types$",                            "READ_APPOINTMENT_TYPES"),
    ("POST",   r"^/portal/patients/names-by-hashes$",                     "READ_PATIENT_NAMES"),
    ("GET",    r"^/portal/nurse/patients/search$",                        "SEARCH_PATIENTS"),
    ("GET",    r"^/portal/patients/[^/]+/encounters$",                    "READ_ENCOUNTERS"),
    ("GET",    r"^/portal/patients/[^/]+/diagnoses$",                     "READ_DIAGNOSES"),
    ("GET",    r"^/portal/patients/[^/]+/allergies$",                     "READ_ALLERGIES"),
    ("GET",    r"^/portal/patients/[^/]+/surgery-histories$",             "READ_SURGERY_HISTORIES"),
    ("GET",    r"^/portal/patients/[^/]+/verify$",                        "VERIFY_PATIENT"),
    ("GET",    r"^/portal/patients/[^/]+$",                               "READ_PATIENT_DETAIL"),
    ("POST",   r"^/portal/users$",                                        "CREATE_USER"),
    ("GET",    r"^/portal/admin/audit-logs$",                             "READ_AUDIT_LOGS"),
    ("GET",    r"^/portal/admin/password-policy$",                        "READ_PASSWORD_POLICY"),
    ("PATCH",  r"^/portal/admin/password-policy$",                        "UPDATE_PASSWORD_POLICY"),
]

TARGET_TABLE_MAP = [
    (r"^/staff/auth",                              "users"),
    (r"^/staff/admin/users",                       "users"),
    (r"^/staff/admin/password-policy",             "password_policy"),
    (r"^/staff/admin/roles",                       "roles"),
    (r"^/staff/admin/audit-logs",                  "audit_logs"),
    (r"^/staff/portal/staff/appointments",         "appointments"),
    (r"^/staff/portal/staff/wards",                "wards"),
    (r"^/staff/portal/doctor/patients",            "sync_patients"),
    (r"^/staff/portal/doctor/schedule",            "appointments"),
    (r"^/staff/emr/doctor/patients",               "patients"),
    (r"^/staff/emr/doctor/encounters",             "encounters"),
    (r"^/staff/emr/patients",                      "patients"),
    (r"^/staff/emr/encounters",                    "encounters"),
    (r"^/staff/emr/nurse/encounters",              "encounters"),
    (r"^/staff/emr/ward-assignments",              "ward_assignments"),
    (r"^/staff/emr/wards",                         "wards"),
    (r"^/patient/auth",                            "users"),
    (r"^/patient/portal/appointments",             "appointments"),
    (r"^/portal/auth",                             "users"),
    (r"^/portal/appointments",                     "appointments"),
    (r"^/portal/staff/appointments",               "appointments"),
    (r"^/portal/patients",                         "patients"),
    (r"^/portal/admin/password-policy",            "password_policy"),
    (r"^/portal/users",                            "users"),
]


# ── 헬퍼 ─────────────────────────────────────────────────────

def _get_action_type(method: str, path: str) -> str:
    for m, pattern, action in ACTION_MAP:
        if m == method and re.match(pattern, path):
            return action
    return "UNKNOWN"


def _get_target_table(path: str) -> str | None:
    for pattern, table in TARGET_TABLE_MAP:
        if re.match(pattern, path):
            return table
    return None


def _get_target_id(path: str) -> str | None:
    match = UUID_PATTERN.search(path)
    return match.group() if match else None


def _decode_token_silent(request: Request) -> dict:
    token = request.cookies.get("access_token")
    if not token:
        return {}
    # 260601 박경수 수정 - current 키 실패 시 previous 키로 재시도 (JWT 로테이션 grace period)
    for secret in filter(None, [JWT_SECRET, JWT_SECRET_PREVIOUS]):
        try:
            return jwt.decode(token, secret, algorithms=[JWT_ALGORITHM])
        except JWTError:
            continue
    return {}


def _get_client_ip(request: Request) -> str | None:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


# ── 세션 만료 경고 미들웨어 ──────────────────────────────────────

class SessionExpiryMiddleware(BaseHTTPMiddleware):
    """액세스 토큰 잔여 시간이 SESSION_WARN_SECONDS 미만이면 응답 헤더에 경고 추가.

    X-Session-Expiring-Soon: true
    X-Session-Remaining-Seconds: <초>
    """

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        token = request.cookies.get("access_token")
        if not token:
            return response

        # 260601 박경수 수정 - current 키 실패 시 previous 키로 재시도 (JWT 로테이션 grace period)
        payload = None
        for secret in filter(None, [JWT_SECRET, JWT_SECRET_PREVIOUS]):
            try:
                payload = jwt.decode(token, secret, algorithms=[JWT_ALGORITHM])
                break
            except JWTError:
                continue
        if payload:
            exp = payload.get("exp")
            if exp:
                remaining = int(exp - datetime.now(timezone.utc).timestamp())
                if 0 < remaining < SESSION_WARN_SECONDS:
                    response.headers["X-Session-Expiring-Soon"]     = "true"
                    response.headers["X-Session-Remaining-Seconds"] = str(remaining)

        return response


# ── 감사 로그 미들웨어 (ISMS-P 2.9.1) ─────────────────────────

class AuditLogMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        if request.url.path in SKIP_AUDIT_PATHS:
            return response

        # 260605 김강환 수정 - DB 저장과 Wazuh stdout 예외 분리 (이중 보존 신뢰성 확보)
        # 공통 데이터 추출
        payload       = _decode_token_silent(request)
        user_id_str   = payload.get("sub")
        target_id_str = _get_target_id(request.url.path)


        action_type   = _get_action_type(request.method, request.url.path)
        client_ip     = _get_client_ip(request)
        result_code   = str(response.status_code)

        # ── DB 저장 (audit_logs) ──────────────────────────────
        # 260612 박경수: RLS enforce 대응 — 직접 INSERT는 SET ROLE 안 된 동적 사용자라
        # 권한 없음. log_audit() SECURITY DEFINER 함수 경유로 교체. (onprem 전용: patient_id UUID)
        try:
            from sqlalchemy import text
            pid = payload.get("pid")
            db = SessionLocal()
            try:
                db.execute(
                    text(
                        "SELECT log_audit("
                        "CAST(:user_id AS uuid), CAST(:patient_id AS uuid), :action, "
                        ":target_table, CAST(:target_id AS uuid), CAST(:source_ip AS inet), :result)"
                    ),
                    {
                        "user_id":      user_id_str or None,
                        "patient_id":   pid or None,
                        "action":       action_type,
                        "target_table": _get_target_table(request.url.path),
                        "target_id":    target_id_str or None,
                        "source_ip":    client_ip,
                        "result":       result_code,
                    },
                )
                db.commit()
            finally:
                db.close()
        except Exception:
            pass  # DB 실패가 응답에 영향 주지 않도록

        # ── Wazuh stdout 출력 (DB 실패와 독립적으로 실행) ──────────
        # pid(patient_id_hash)는 인자로 넘기지 않음 → stdout 미포함 (DB에만 저장)
        try:
            _emit_wazuh_log(
                action_type = action_type,
                result_code = result_code,
                user_id     = user_id_str,
                source_ip   = client_ip,
                path        = request.url.path,   # 함수 내부에서 UUID 마스킹됨
                method      = request.method,
                role        = payload.get("role"),
            )
        except Exception:
            pass  # stdout 실패가 응답/DB에 영향 주지 않도록

        return response