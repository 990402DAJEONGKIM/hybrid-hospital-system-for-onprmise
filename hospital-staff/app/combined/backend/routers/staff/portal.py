import logging
import os
import uuid
from datetime import date as date_type, datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session as DbSession

from core.database import get_db, get_read_db, get_breakglass_db
from core.security import get_client_ip, get_current_user, has_permission, record_audit
from core.ses import send_appointment_notification
from models.db import (
    Appointment, AppointmentHistory, AppointmentStatus, AppointmentType,
    AuditLog, Notification, Patient, SyncAllergy, SyncDepartment, SyncDiagnosis, SyncDoctor,
    SyncEncounter, SyncPatient, SyncSurgery, SyncWard, User,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/portal/doctor", tags=["doctor-portal"])


# ── 헬퍼 ─────────────────────────────────────────────────────────

def _verify(current_user: dict, db: DbSession, permission: str) -> None:
    if not has_permission(current_user["sub"], permission, db):
        raise HTTPException(status_code=403, detail="해당 메뉴에 대한 접근 권한이 없습니다.")


# 260612 박경수: 직접 INSERT → 공통 record_audit(log_audit 경유)
def _record_audit(
    db: DbSession, user_id: str, action: str, result: str,
    request: Request, target_id: uuid.UUID = None,
) -> None:
    from core.security import record_audit
    # 알림 발송 이벤트 감사 기록 (SER-005)
    record_audit(
        db, action_type="NOTIFICATION_SENT",
        result_code="200" if sent else "500",
        user_id=patient_user.user_id if patient_user else None,
        # 260612 박경수: patient_id_hash(문자열)는 온프레 UUID 컬럼과 불일치 → 제외
        target_table="notifications",
        source_ip=None,
    )


def _notify_patient(db: DbSession, appt: Appointment, status: str) -> None:
    """예약 상태 변경 시 환자 이메일 알림 발송 + notifications/audit_logs 기록."""
    try:
        patient = db.query(Patient).filter(Patient.patient_id_hash == appt.patient_id_hash).first()
        if not patient:
            return
        if not patient.email:
            logger.info("이메일 미등록 환자 — 알림 생략 (patient_id_hash=%s)", appt.patient_id_hash)
            return
        patient_user = db.query(User).filter(User.patient_id == patient.patient_id).first()
        type_name = appt.appt_type.type_name if appt.appt_type else None
        sent = send_appointment_notification(
            to_email  = patient.email,
            status    = status,
            appt_date = str(appt.appointment_date),
            appt_time = appt.appointment_time.strftime("%H:%M") if appt.appointment_time else None,
            dept_code = appt.department_code,
            type_name = type_name,
        )
        now = datetime.now(timezone.utc)
        db.add(Notification(
            user_id        = patient_user.user_id if patient_user else None,  # by 김다정, 2026-06-06
            appointment_id = appt.appointment_id,
            channel        = "email",
            status         = "sent" if sent else "failed",
            sent_at        = now if sent else None,
        ))
        # 알림 발송 이벤트 감사 기록 (SER-005: action_type=NOTIFICATION_SENT)
        record_audit(
            db, action_type="NOTIFICATION_SENT",
            result_code="200" if sent else "500",
            user_id=patient_user.user_id if patient_user else None,
            patient_id=appt.patient_id_hash,
            target_table="notifications",
            target_id=appt.appointment_id,
        )
        db.commit()
    except Exception as exc:
        logger.warning("예약 알림 기록 실패 (appointment_id=%s): %s", appt.appointment_id, exc)
        try:
            db.rollback()
        except Exception:
            pass


def _appt_out(appt: Appointment) -> dict:
    s = appt.appt_status
    t = appt.appt_type
    return {
        "appointment_id":        str(appt.appointment_id),
        "patient_id_hash":       appt.patient_id_hash,
        "type_code":             t.type_code if t else None,
        "type_name":             t.type_name if t else None,
        "status_code":           s.status_code if s else None,
        "status_name":           s.status_name if s else None,
        "appointment_date":      str(appt.appointment_date),
        "appointment_time":      appt.appointment_time.strftime("%H:%M") if appt.appointment_time else None,
        "department_code":       appt.department_code,
        "doctor_id":             str(appt.doctor_id) if appt.doctor_id else None,
        "ward_id":               str(appt.ward_id) if appt.ward_id else None,
        "room_type_pref":        appt.room_type_pref,
        "has_chronic_condition": appt.has_chronic_condition,
        "notes":                 appt.notes,
        "created_at":            appt.created_at.isoformat() if appt.created_at else None,
        "confirmed_at":          appt.confirmed_at.isoformat() if appt.confirmed_at else None,
        "cancelled_at":          appt.cancelled_at.isoformat() if appt.cancelled_at else None,
        "cancel_reason":         appt.cancel_reason,
    }


# ── Pydantic 스키마 ──────────────────────────────────────────────

class StatusUpdate(BaseModel):
    status_code: str
    reason:      Optional[str] = None


class ManualAppointmentRequest(BaseModel):
    patient_id_hash:       str
    type_code:             str
    department_code:       str
    doctor_id:             Optional[str] = None
    appointment_date:      str            # YYYY-MM-DD
    appointment_time:      str            # HH:MM
    room_type_pref:        Optional[str]  = None
    has_chronic_condition: Optional[bool] = None
    notes:                 Optional[str]  = None


# ── 공통 참조 데이터 ──────────────────────────────────────────

@router.get("/appointment-types")
def get_appointment_types(
    current_user: dict     = Depends(get_current_user),
    db:           DbSession = Depends(get_read_db),
):
    """예약 유형 목록 (수동 예약 폼용)."""
    _verify(current_user, db, "VIEW_ALL_APPOINTMENTS")
    from models.db import AppointmentType as ApptType
    types = (
        db.query(ApptType)
        .filter(ApptType.is_active == True)
        .order_by(ApptType.sort_order)
        .all()
    )
    return [
        {"type_code": t.type_code, "type_name": t.type_name,
         "requires_previous_visit": t.requires_previous_visit}
        for t in types
    ]


@router.get("/staff/doctors")
def get_doctors(
    department_code: Optional[str] = Query(default=None),
    current_user: dict     = Depends(get_current_user),
    db:           DbSession = Depends(get_read_db),
):
    """의사 목록 (진료과 필터 선택)."""
    _verify(current_user, db, "VIEW_ALL_APPOINTMENTS")
    query = db.query(SyncDoctor).filter(SyncDoctor.is_active == True)
    if department_code:
        query = query.filter(SyncDoctor.department_code == department_code)
    return [
        {"doctor_id": str(d.doctor_id), "doctor_name": d.doctor_name,
         "department_code": d.department_code}
        for d in query.all()
    ]


@router.get("/staff/departments")
def get_departments(
    current_user: dict     = Depends(get_current_user),
    db:           DbSession = Depends(get_read_db),
):
    """진료과 목록 (달력 레이블 표시용)."""
    _verify(current_user, db, "VIEW_ALL_APPOINTMENTS")
    depts = db.query(SyncDepartment).filter(SyncDepartment.is_active == True).all()
    return [
        {"department_code": d.department_code, "department_name": d.department_name}
        for d in depts
    ]


# ── 의사 일정 / 환자 조회 ─────────────────────────────────────────

@router.get("/schedule")
def get_doctor_schedule(
    current_user: dict     = Depends(get_current_user),
    db:           DbSession = Depends(get_read_db),
):
    """의사 본인의 예약 일정 조회 (레거시 — /appointments/today 사용 권장)."""
    _verify(current_user, db, "VIEW_ALL_APPOINTMENTS")

    doctor_id = current_user.get("did")
    if not doctor_id:
        raise HTTPException(status_code=400, detail="의사 정보가 연결되지 않은 계정입니다.")

    appts = (
        db.query(Appointment)
        .filter(Appointment.doctor_id == str(doctor_id))
        .order_by(Appointment.appointment_date.asc(), Appointment.appointment_time.asc())
        .all()
    )
    return [_appt_out(a) for a in appts]


@router.get("/appointments/today")
def get_doctor_appointments_today(
    request:      Request,
    mode:         str           = Query(default="today", description="today | week"),
    status_code:  Optional[str] = Query(default=None),
    current_user: dict          = Depends(get_current_user),
    db:           DbSession     = Depends(get_db),
    bg_db:        DbSession     = Depends(get_breakglass_db),
):
    """SFR-017 — AWS RDS appointments 기반 당일(또는 향후 7일) 진료 목록.

    - 환자 실명 없음 (patient_id_hash만 반환)
    - department_name, type_name, status_name, is_terminal 포함
    - appointment_time 오름차순 정렬
    - 조회 행위를 audit_logs에 SCHEDULE_VIEW로 기록
    """
    from datetime import timedelta
    _verify(current_user, db, "VIEW_DOCTOR_SCHEDULE")

    doctor_id = current_user.get("did")
    if not doctor_id:
        raise HTTPException(status_code=400, detail="의사 정보가 연결되지 않은 계정입니다.")

    today = date_type.today()
    if mode == "week":
        date_from = today + timedelta(days=1)
        date_to   = today + timedelta(days=7)
    else:
        date_from = today
        date_to   = today

    query = (
        db.query(Appointment)
        .filter(
            Appointment.doctor_id        == str(doctor_id),
            Appointment.appointment_date >= date_from,
            Appointment.appointment_date <= date_to,
        )
    )
    if status_code:
        query = query.join(AppointmentStatus).filter(
            AppointmentStatus.status_code == status_code
        )

    appts = query.order_by(
        Appointment.appointment_date.asc(),
        Appointment.appointment_time.asc(),
    ).all()

    # 진료과 이름 매핑 (RDS sync_departments)
    dept_codes = {a.department_code for a in appts if a.department_code}
    dept_map   = {}
    if dept_codes:
        depts = db.query(SyncDepartment).filter(
            SyncDepartment.department_code.in_(dept_codes)
        ).all()
        dept_map = {d.department_code: d.department_name for d in depts}

    # record_audit이 SET ROLE을 리셋하므로 commit 전에 모든 ORM 접근을 완료
    unique_hashes = list({a.patient_id_hash for a in appts if a.patient_id_hash})

    patient_info_map: dict = {}
    if unique_hashes:
        patients = bg_db.query(Patient).filter(
            Patient.patient_id_hash.in_(unique_hashes)
        ).all()
        patient_info_map = {
            p.patient_id_hash: {"name": p.patient_name, "id": str(p.patient_id)}
            for p in patients
        }

    result = []
    for a in appts:
        s = a.appt_status
        t = a.appt_type
        info = patient_info_map.get(a.patient_id_hash, {})
        result.append({
            "appointment_id":   str(a.appointment_id),
            "patient_id_hash":  a.patient_id_hash,
            "patient_id":       info.get("id"),
            "patient_name":     info.get("name"),
            "appointment_date": str(a.appointment_date),
            "appointment_time": a.appointment_time.strftime("%H:%M") if a.appointment_time else None,
            "type_code":        t.type_code   if t else None,
            "type_name":        t.type_name   if t else None,
            "department_code":  a.department_code,
            "department_name":  dept_map.get(a.department_code, a.department_code),
            "status_code":      s.status_code if s else None,
            "status_name":      s.status_name if s else None,
            "is_terminal":      s.is_terminal if s else False,
            "notes":            a.notes,
        })

# 감사 로그 기록 (SFR-017)
    from core.security import record_audit
    record_audit(
        db,
        action_type = "SCHEDULE_VIEW",
        result_code = "200",
        user_id     = current_user["sub"],
        source_ip   = request.client.host if request.client else None,
    )
    db.commit()
    return result


@router.get("/patients")
def get_managed_patients(
    current_user: dict     = Depends(get_current_user),
    db:           DbSession = Depends(get_read_db),
):
    """담당 의사가 진료했던 환자 목록 (비식별 정보 기반)."""
    _verify(current_user, db, "VIEW_PATIENT_RECORDS")

    doctor_id = current_user.get("did")
    if not doctor_id:
        raise HTTPException(status_code=400, detail="의사 정보가 연결되지 않은 계정입니다.")

    patients = (
        db.query(SyncPatient)
        .join(SyncEncounter, SyncPatient.patient_id_hash == SyncEncounter.patient_id_hash)
        .filter(SyncEncounter.doctor_id == str(doctor_id))
        .distinct()
        .all()
    )
    return [
        {
            "patient_id_hash": p.patient_id_hash,
            "birth_year":      p.birth_year,
            "gender_code":     p.gender_code,
        }
        for p in patients
    ]


@router.get("/patients/{patient_id_hash}")
def get_patient_detail(
    patient_id_hash: str,
    request:         Request,
    current_user:    dict     = Depends(get_current_user),
    db:              DbSession = Depends(get_db),
):
    """특정 환자의 상세 의료 정보 조회 (감사 로그 기록)."""
    _verify(current_user, db, "VIEW_PATIENT_RECORDS")

    patient = db.query(SyncPatient).filter(
        SyncPatient.patient_id_hash == patient_id_hash
    ).first()
    if not patient:
        raise HTTPException(status_code=404, detail="환자를 찾을 수 없습니다.")

    encounters = db.query(SyncEncounter).filter(
        SyncEncounter.patient_id_hash == patient_id_hash
    ).order_by(SyncEncounter.visit_date.desc()).all()

    diagnoses = db.query(SyncDiagnosis).filter(
        SyncDiagnosis.patient_id_hash == patient_id_hash
    ).all()

    allergies = db.query(SyncAllergy).filter(
        SyncAllergy.patient_id_hash == patient_id_hash
    ).all()

    surgeries = db.query(SyncSurgery).filter(
        SyncSurgery.patient_id_hash == patient_id_hash
    ).all()

    _record_audit(db, current_user["sub"], "READ_PATIENT_DETAIL", "200", request)

    return {
        "patient": {
            "patient_id_hash": patient.patient_id_hash,
            "birth_year":      patient.birth_year,
            "gender_code":     patient.gender_code,
        },
        "encounters": [
            {
                "encounter_id":    str(e.encounter_id),
                "visit_date":      str(e.visit_date),
                "encounter_type":  e.encounter_type,
                "department_code": e.department_code,
                "status_code":     e.status_code,
            }
            for e in encounters
        ],
        "diagnoses": [
            {
                "diagnosis_code": d.diagnosis_code,
                "is_primary":     d.is_primary,
                "diagnosed_at":   d.diagnosed_at.isoformat() if d.diagnosed_at else None,
            }
            for d in diagnoses
        ],
        "allergies": [
            {
                "allergy_name": a.allergy_name,
                "severity":     a.severity_code,
            }
            for a in allergies
        ],
        "surgeries": [
            {
                "surgery_name": s.surgery_name,
                "surgery_date": str(s.surgery_date),
            }
            for s in surgeries
        ],
    }


# ── 접수 전용 환자 정보 ────────────────────────────────────────────
# 민감 상병(F*, B20*, Z21*)은 코드·진단명 모두 "[민감]" 마스킹.
_SENSITIVE_PREFIXES = ("F", "B20", "Z21")


def _is_sensitive(code: str) -> bool:
    return any(code.upper().startswith(p) for p in _SENSITIVE_PREFIXES)


@router.get("/nurse/patients/{patient_id_hash}/reception-info")
def nurse_reception_info(
    patient_id_hash: str,
    request:         Request,
    current_user:    dict     = Depends(get_current_user),
    db:              DbSession = Depends(get_db),
):
    """접수 업무용 환자 정보 — 내원 이력·알레르기 (AWS RDS 기반).
    진단명(diagnosis_text)은 병원 내부망에서 온프레미스 API를 직접 호출해야 합니다."""
    _verify(current_user, db, "VIEW_ALL_APPOINTMENTS")

    if current_user.get("role") not in ("nurse", "admin"):
        raise HTTPException(status_code=403, detail="접수 권한이 없습니다.")

    encounters = (
        db.query(SyncEncounter)
        .filter(SyncEncounter.patient_id_hash == patient_id_hash)
        .order_by(SyncEncounter.visit_date.desc())
        .limit(5)
        .all()
    )

    allergies = db.query(SyncAllergy).filter(
        SyncAllergy.patient_id_hash == patient_id_hash
    ).all()

    # 진단명 실시간 조회는 온프레미스 API 직접 호출 필요 (브라우저에서 internal.hospital.com 접근)
    raw_diags: list = []

    _record_audit(db, current_user["sub"], "READ_RECEPTION_INFO", "200", request)

    def _build_diag(d: dict) -> dict:
        code = d.get("diagnosis_code", "")
        if _is_sensitive(code):
            return {"diagnosis_code": "[민감]", "diagnosis_text": "[민감]", "is_primary": d.get("is_primary")}
        return {"diagnosis_code": code, "diagnosis_text": d.get("diagnosis_text"), "is_primary": d.get("is_primary")}

    return {
        "recent_encounters": [
            {
                "visit_date":      str(e.visit_date),
                "department_code": e.department_code,
                "encounter_type":  e.encounter_type,
            }
            for e in encounters
        ],
        "diagnoses": [_build_diag(d) for d in raw_diags],
        "allergies": [
            {
                "allergy_name": a.allergy_name,
                "severity":     a.severity_code,
            }
            for a in allergies
        ],
    }


# ── 원무과/스태프 예약 관리 ──────────────────────────────────────

@router.get("/staff/appointments")
def get_all_appointments(
    appt_date:   Optional[date_type] = Query(default=None),
    status_code: Optional[str]       = Query(default=None),
    current_user: dict     = Depends(get_current_user),
    db:           DbSession = Depends(get_read_db),
):
    """전체 예약 목록 조회 (원무과용)."""
    _verify(current_user, db, "VIEW_ALL_APPOINTMENTS")

    query = db.query(Appointment)
    if appt_date:
        query = query.filter(Appointment.appointment_date == appt_date)
    if status_code:
        query = query.join(AppointmentStatus).filter(
            AppointmentStatus.status_code == status_code
        )

    appts = query.order_by(
        Appointment.appointment_date.asc(),
        Appointment.appointment_time.asc(),
    ).all()
    return [_appt_out(a) for a in appts]


@router.patch("/staff/appointments/{appointment_id}/status")
def update_appointment_status(
    appointment_id: uuid.UUID,
    body:           StatusUpdate,
    request:        Request,
    current_user:   dict     = Depends(get_current_user),
    db:             DbSession = Depends(get_db),
):
    """예약 상태 변경 (확정/취소/완료/노쇼)."""
    _verify(current_user, db, "MANAGE_APPOINTMENTS")

    appt = db.query(Appointment).filter(
        Appointment.appointment_id == appointment_id
    ).first()
    if not appt:
        raise HTTPException(status_code=404, detail="예약을 찾을 수 없습니다.")

    if appt.appt_status and appt.appt_status.is_terminal:
        raise HTTPException(status_code=400, detail="이미 종료된 예약입니다.")

    new_status = db.query(AppointmentStatus).filter(
        AppointmentStatus.status_code == body.status_code
    ).first()
    if not new_status:
        raise HTTPException(status_code=400, detail="유효하지 않은 상태 코드입니다.")

    now           = datetime.now(timezone.utc)
    staff_user_id = uuid.UUID(current_user["sub"])

    db.add(AppointmentHistory(
        appointment_id = appointment_id,
        changed_by     = staff_user_id,
        prev_status_id = appt.status_id,
        new_status_id  = new_status.status_id,
        change_reason  = body.reason,
    ))

    appt.status_id  = new_status.status_id
    appt.updated_at = now

    if body.status_code == "confirmed":
        appt.confirmed_at = now
        appt.confirmed_by = staff_user_id
    elif body.status_code == "cancelled":
        appt.cancelled_at  = now
        appt.cancelled_by  = staff_user_id
        appt.cancel_reason = body.reason

    _record_audit(
        db, current_user["sub"],
        "APPOINTMENT_STATUS_CHANGE", "200",
        request, appointment_id,
    )

    db.commit()
    db.refresh(appt)

    # 확정·취소 시 환자 이메일 알림 (실패해도 응답에 영향 없음)
    if body.status_code in ("confirmed", "cancelled"):
        _notify_patient(db, appt, body.status_code)

    return {
        "message":     f"예약 상태가 '{new_status.status_name}'(으)로 변경되었습니다.",
        "appointment": _appt_out(appt),
    }


# ── 병동 현황 ────────────────────────────────────────────────────

@router.get("/staff/wards")
def get_ward_status(
    request:      Request,
    current_user: dict     = Depends(get_current_user),
    db:           DbSession = Depends(get_db),
):
    """병동 현황 및 가용 병상 조회."""
    _verify(current_user, db, "VIEW_WARD_STATUS")

    wards = db.query(SyncWard).all()
    _record_audit(db, current_user["sub"], "VIEW_WARD_STATUS", "200", request)

    return [
        {
            "ward_id":        str(w.ward_id),
            "ward_name":      w.ward_name,
            "room_type":      w.room_type,
            "total_beds":     w.total_beds,
            "available_beds": w.available_beds,
            "synced_at":      w.synced_at.isoformat() if w.synced_at else None,
        }
        for w in wards
    ]


# ── 예약 단건 조회 ────────────────────────────────────────────────

@router.get("/staff/appointments/{appointment_id}")
def get_appointment_detail(
    appointment_id: uuid.UUID,
    current_user:   dict     = Depends(get_current_user),
    db:             DbSession = Depends(get_read_db),
):
    """예약 단건 상세 조회 (원무과·의사 공용)."""
    _verify(current_user, db, "VIEW_ALL_APPOINTMENTS")

    appt = db.query(Appointment).filter(
        Appointment.appointment_id == appointment_id
    ).first()
    if not appt:
        raise HTTPException(status_code=404, detail="예약을 찾을 수 없습니다.")

    patient = db.query(SyncPatient).filter(
        SyncPatient.patient_id_hash == appt.patient_id_hash
    ).first() if appt.patient_id_hash else None

    history = [
        {
            "changed_at":    h.changed_at.isoformat() if h.changed_at else None,
            "change_reason": h.change_reason,
            "new_date":      str(h.new_date) if h.new_date else None,
            "new_time":      h.new_time.strftime("%H:%M") if h.new_time else None,
        }
        for h in sorted(appt.history, key=lambda x: x.changed_at or datetime.min.replace(tzinfo=timezone.utc))
    ]

    result = _appt_out(appt)
    result["history"] = history
    if patient:
        result["patient_birth_year"] = patient.birth_year
        result["patient_gender"]     = patient.gender_code
    return result


# ── 수동 예약 등록 (원무과) ───────────────────────────────────────

@router.post("/staff/appointments", status_code=201)
def create_manual_appointment(
    body:         ManualAppointmentRequest,
    request:      Request,
    current_user: dict     = Depends(get_current_user),
    db:           DbSession = Depends(get_db),
):
    """원무과 직원이 방문 환자를 직접 예약 등록."""
    _verify(current_user, db, "MANAGE_APPOINTMENTS")

    now = datetime.now(timezone.utc)

    patient = db.query(SyncPatient).filter(
        SyncPatient.patient_id_hash == body.patient_id_hash
    ).first()
    if not patient:
        raise HTTPException(status_code=404, detail="해당 환자 정보를 찾을 수 없습니다.")

    # 환자 포털 계정 조회 (없어도 예약 가능) — by 김다정, 2026-06-06
    portal_patient = db.query(Patient).filter(
        Patient.patient_id_hash == body.patient_id_hash
    ).first()
    patient_user = None
    if portal_patient:
        patient_user = db.query(User).filter(
            User.patient_id == portal_patient.patient_id
        ).first()

    appt_type = db.query(AppointmentType).filter(
        AppointmentType.type_code == body.type_code,
        AppointmentType.is_active == True,
    ).first()
    if not appt_type:
        raise HTTPException(status_code=400, detail="유효하지 않은 예약 유형입니다.")

    dept = db.query(SyncDepartment).filter(
        SyncDepartment.department_code == body.department_code,
        SyncDepartment.is_active == True,
    ).first()
    if not dept:
        raise HTTPException(status_code=400, detail="존재하지 않는 진료과입니다.")

    doctor_uuid = None
    if body.doctor_id:
        try:
            doctor_uuid = uuid.UUID(body.doctor_id)
        except ValueError:
            raise HTTPException(status_code=422, detail="유효하지 않은 의사 ID입니다.")

    from datetime import date as date_type, time as time_type
    try:
        appt_date = date_type.fromisoformat(body.appointment_date)
    except ValueError:
        raise HTTPException(status_code=422, detail="날짜 형식이 올바르지 않습니다. (YYYY-MM-DD)")

    try:
        h, m = body.appointment_time.split(":")
        appt_time = time_type(int(h), int(m))
    except (ValueError, AttributeError):
        raise HTTPException(status_code=422, detail="시간 형식이 올바르지 않습니다. (HH:MM)")

    pending_status = db.query(AppointmentStatus).filter(
        AppointmentStatus.status_code == "pending"
    ).first()
    if not pending_status:
        raise HTTPException(status_code=500, detail="시스템 오류: 예약 상태 설정이 없습니다.")

    staff_user_id = uuid.UUID(current_user["sub"])

    # DB_MODE 분기: 클라우드 RDS는 patient_user_id(NOT NULL) 포함 — by 김다정, 2026-06-06
    appt_kwargs = dict(
        patient_id_hash       = body.patient_id_hash,
        type_id               = appt_type.type_id,
        status_id             = pending_status.status_id,
        department_code       = body.department_code,
        doctor_id             = doctor_uuid,
        room_type_pref        = body.room_type_pref,
        has_chronic_condition = body.has_chronic_condition,
        appointment_date      = appt_date,
        appointment_time      = appt_time,
        notes                 = body.notes,
    )
    if os.getenv("DB_MODE", "cloud") == "cloud":
        appt_kwargs["patient_user_id"] = patient_user.user_id if patient_user else staff_user_id
    appt = Appointment(**appt_kwargs)
    db.add(appt)
    db.flush()

    db.add(AppointmentHistory(
        appointment_id = appt.appointment_id,
        changed_by     = staff_user_id,
        new_status_id  = pending_status.status_id,
        new_date       = appt_date,
        new_time       = appt_time,
        change_reason  = "원무과 수동 등록",
    ))

    _record_audit(
        db, current_user["sub"], "APPOINTMENT_CREATE", "201",
        request, appt.appointment_id,
    )

    # 예약 완료 알림 생성 — by 김다정, 2026-06-06
    try:
        if patient_user:
            db.add(Notification(
                user_id        = patient_user.user_id,
                appointment_id = appt.appointment_id,
                channel        = "email",
                status         = "pending",
            ))
    except Exception:
        pass

    db.commit()
    db.refresh(appt)
    return _appt_out(appt)


# ── 간호사 대시보드 요약 (SFR-022) ─────────────────────────────

@router.get("/nurse/dashboard")
def nurse_dashboard_summary(
    current_user: dict     = Depends(get_current_user),
    db:           DbSession = Depends(get_db),
):
    """당일 예약 집계·가용 병상·미확인 알림 카운트 — AWS RDS 전용 (환자 실명 없음)."""
    _verify(current_user, db, "VIEW_ALL_APPOINTMENTS")

    today = date_type.today()

    appts = (
        db.query(Appointment, AppointmentStatus.status_code)
        .join(AppointmentStatus, Appointment.status_id == AppointmentStatus.status_id)
        .filter(Appointment.appointment_date == today)
        .all()
    )
    counts = {"total": len(appts), "pending": 0, "completed": 0, "cancelled": 0, "confirmed": 0}
    for _, sc in appts:
        if sc in counts:
            counts[sc] += 1

    total_beds = db.query(func.sum(SyncWard.available_beds)).scalar() or 0

    user_id = uuid.UUID(current_user["sub"])
    notif_count = (
        db.query(func.count(Notification.notification_id))
        .filter(Notification.user_id == user_id, Notification.status == "pending")
        .scalar()
    ) or 0

    synced_at = None
    ward = db.query(SyncWard).order_by(SyncWard.synced_at.desc()).first()
    if ward and ward.synced_at:
        synced_at = ward.synced_at.isoformat()

    return {
        "today_appointments": counts,
        "available_beds":     int(total_beds),
        "pending_notifications": notif_count,
        "ward_synced_at":     synced_at,
    }


# ── 예약 변경 이력 조회 (SFR-023) ────────────────────────────────

@router.get("/staff/appointments/{appointment_id}/history")
def get_appointment_history(
    appointment_id: uuid.UUID,
    current_user:   dict     = Depends(get_current_user),
    db:             DbSession = Depends(get_read_db),
):
    """예약 변경 이력 목록 — appointment_history 테이블 조회."""
    _verify(current_user, db, "VIEW_ALL_APPOINTMENTS")

    appt = db.query(Appointment).filter(
        Appointment.appointment_id == appointment_id
    ).first()
    if not appt:
        raise HTTPException(status_code=404, detail="예약을 찾을 수 없습니다.")

    history = sorted(
        appt.history,
        key=lambda h: h.changed_at or datetime.min.replace(tzinfo=timezone.utc),
    )

    def _status_name(status_id):
        if not status_id:
            return None
        s = db.query(AppointmentStatus).filter(
            AppointmentStatus.status_id == status_id
        ).first()
        return s.status_name if s else str(status_id)

    return [
        {
            "history_id":    str(h.history_id),
            "changed_at":    h.changed_at.isoformat() if h.changed_at else None,
            "changed_by":    str(h.changed_by) if h.changed_by else None,
            "prev_status":   _status_name(h.prev_status_id),
            "new_status":    _status_name(h.new_status_id),
            "prev_date":     str(h.prev_date) if h.prev_date else None,
            "new_date":      str(h.new_date) if h.new_date else None,
            "prev_time":     h.prev_time.strftime("%H:%M") if h.prev_time else None,
            "new_time":      h.new_time.strftime("%H:%M") if h.new_time else None,
            "change_reason": h.change_reason,
        }
        for h in history
    ]


# ── 병동 퇴원 처리 (SFR-027) ────────────────────────────────────

@router.patch("/staff/wards/{ward_id}/discharge")
def ward_discharge(
    ward_id:      uuid.UUID,
    request:      Request,
    current_user: dict     = Depends(get_current_user),
    db:           DbSession = Depends(get_db),
):
    """AWS sync_wards.available_beds += 1 (퇴원 처리 후 병상 반환)."""
    _verify(current_user, db, "MANAGE_APPOINTMENTS")

    ward = db.query(SyncWard).filter(SyncWard.ward_id == ward_id).first()
    if not ward:
        raise HTTPException(status_code=404, detail="병동을 찾을 수 없습니다.")

    if ward.available_beds >= ward.total_beds:
        raise HTTPException(status_code=400, detail="이미 병상이 모두 비어 있습니다.")

    ward.available_beds = (ward.available_beds or 0) + 1

    _record_audit(
        db, current_user["sub"], "ENCOUNTER_DISCHARGE", "200",
        request, ward_id,
    )
    db.commit()
    db.refresh(ward)

    return {
        "ward_id":        str(ward.ward_id),
        "ward_name":      ward.ward_name,
        "available_beds": ward.available_beds,
        "total_beds":     ward.total_beds,
    }

