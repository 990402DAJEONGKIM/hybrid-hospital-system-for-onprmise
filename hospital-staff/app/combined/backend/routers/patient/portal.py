import logging
import uuid as uuid_module
from datetime import date as date_type, datetime, timezone
from datetime import time as time_type
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session as DbSession

from core.database import get_db, get_read_db
from core.security import get_current_user, record_audit
from core.ses import send_appointment_notification
from models.db import (
    Appointment, AppointmentHistory, AppointmentStatus, AppointmentType,
    Notification, Patient, SyncAllergy, SyncDepartment, SyncDiagnosis, SyncDoctor,
    SyncEncounter, SyncPatient, SyncSurgery, SyncWard, User,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/portal", tags=["patient-portal"])


# ── 알림 헬퍼 ────────────────────────────────────────────────────

def _notify_patient(
    db:        DbSession,
    appt:      Appointment,
    status:    str,
    prev_date: Optional[str] = None,
    prev_time: Optional[str] = None,
) -> None:
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
            prev_date = prev_date,
            prev_time = prev_time,
        )
        now = datetime.now(timezone.utc)
        db.add(Notification(
            user_id        = patient_user.user_id if patient_user else None,
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


# ── 직렬화 헬퍼 ──────────────────────────────────────────────────

def _appt_out(appt: Appointment, doctor_name: str | None = None) -> dict:
    s = appt.appt_status
    t = appt.appt_type
    return {
        "appointment_id":        str(appt.appointment_id),
        "type_code":             t.type_code if t else None,
        "type_name":             t.type_name if t else None,
        "status_code":           s.status_code if s else None,
        "status_name":           s.status_name if s else None,
        "appointment_date":      str(appt.appointment_date),
        "appointment_time":      appt.appointment_time.strftime("%H:%M") if appt.appointment_time else None,
        "department_code":       appt.department_code,
        "doctor_id":             str(appt.doctor_id) if appt.doctor_id else None,
        "doctor_name":           doctor_name,
        "ward_id":               str(appt.ward_id) if appt.ward_id else None,
        "room_type_pref":        appt.room_type_pref,
        "has_chronic_condition": appt.has_chronic_condition,
        "notes":                 appt.notes,
        "created_at":            appt.created_at.isoformat() if appt.created_at else None,
        "confirmed_at":          appt.confirmed_at.isoformat() if appt.confirmed_at else None,
        "cancelled_at":          appt.cancelled_at.isoformat() if appt.cancelled_at else None,
        "cancel_reason":         appt.cancel_reason,
    }


def _resolve_doctor_name(db: DbSession, doctor_id) -> str | None:
    if not doctor_id:
        return None
    doc = db.query(SyncDoctor).filter(SyncDoctor.doctor_id == doctor_id).first()
    return doc.doctor_name if doc else None


# ── 권한 헬퍼 ────────────────────────────────────────────────────

def _require_patient(current_user: dict) -> str:
    """patient 역할 확인 후 patient_id_hash 반환."""
    if current_user.get("role") != "patient":
        raise HTTPException(status_code=403, detail="환자만 접근할 수 있습니다.")
    pid = current_user.get("pid")
    if not pid:
        raise HTTPException(
            status_code=400,
            detail="연결된 환자 정보가 없습니다. 관리자에게 문의하세요.",
        )
    return pid


def _get_pending_status(db: DbSession) -> AppointmentStatus:
    status = db.query(AppointmentStatus).filter(
        AppointmentStatus.status_code == "pending"
    ).first()
    if not status:
        raise HTTPException(status_code=500, detail="시스템 오류: 예약 상태 설정이 없습니다.")
    return status


# ── Pydantic 스키마 ──────────────────────────────────────────────

class AppointmentCreateRequest(BaseModel):
    type_code:             str
    department_code:       str
    doctor_id:             Optional[str]    = None   # UUID
    appointment_date:      str                        # YYYY-MM-DD
    appointment_time:      str                        # HH:MM
    room_type_pref:        Optional[str]    = None   # 1인실|2인실|다인실
    has_chronic_condition: Optional[bool]   = None
    notes:                 Optional[str]    = None


class AppointmentUpdateRequest(BaseModel):
    appointment_date: Optional[str] = None
    appointment_time: Optional[str] = None
    notes:            Optional[str] = None


# ── 조회용 엔드포인트 (예약 신청 폼 지원) ────────────────────────

@router.get("/appointment-types")
def get_appointment_types(
    current_user: dict     = Depends(get_current_user),
    db:           DbSession = Depends(get_read_db),
):
    """환자 예약 화면용 예약 유형 목록 — 초진(outpatient_new) 제외."""
    types = (
        db.query(AppointmentType)
        .filter(
            AppointmentType.is_active == True,
            AppointmentType.type_code != "outpatient_new",   # SFR-035: 초진 미노출
        )
        .order_by(AppointmentType.sort_order)
        .all()
    )
    return [
        {
            "type_id":                t.type_id,
            "type_code":              t.type_code,
            "type_name":              t.type_name,
            "requires_previous_visit": t.requires_previous_visit,
            "description":            t.description,
        }
        for t in types
    ]


@router.get("/departments")
def get_departments(
    visited_only: bool     = Query(default=False),
    current_user: dict     = Depends(get_current_user),
    db:           DbSession = Depends(get_read_db),
):
    query = db.query(SyncDepartment).filter(SyncDepartment.is_active == True)

    if visited_only:
        pid = current_user.get("pid")
        if pid:
            visited_codes = [
                row[0] for row in
                db.query(SyncEncounter.department_code)
                  .filter(SyncEncounter.patient_id_hash == pid)
                  .distinct()
                  .all()
            ]
            query = query.filter(SyncDepartment.department_code.in_(visited_codes))

    return [
        {"department_code": d.department_code, "department_name": d.department_name}
        for d in query.all()
    ]


@router.get("/doctors")
def get_doctors(
    department_code: Optional[str] = Query(default=None),
    current_user: dict     = Depends(get_current_user),
    db:           DbSession = Depends(get_read_db),
):
    query = db.query(SyncDoctor).filter(SyncDoctor.is_active == True)
    if department_code:
        query = query.filter(SyncDoctor.department_code == department_code)
    return [
        {
            "doctor_id":       str(d.doctor_id),
            "doctor_name":     d.doctor_name,
            "department_code": d.department_code,
        }
        for d in query.all()
    ]


@router.get("/recent-encounter")
def get_recent_encounter(
    current_user: dict     = Depends(get_current_user),
    db:           DbSession = Depends(get_read_db),
):
    """최근 방문 진료과·담당 의사 조회 — 예약 신청 첫 단계 기본값 제안용 (SFR-035)."""
    pid = _require_patient(current_user)

    last = (
        db.query(SyncEncounter)
        .filter(SyncEncounter.patient_id_hash == pid)
        .order_by(SyncEncounter.visit_date.desc())
        .first()
    )
    if not last:
        return {"department_code": None, "department_name": None, "doctor_id": None, "doctor_name": None}

    dept = db.query(SyncDepartment).filter(
        SyncDepartment.department_code == last.department_code
    ).first()

    doctor_name = _resolve_doctor_name(db, last.doctor_id)

    return {
        "department_code": last.department_code,
        "department_name": dept.department_name if dept else last.department_code,
        "doctor_id":       str(last.doctor_id) if last.doctor_id else None,
        "doctor_name":     doctor_name,
    }


# ── 예약 CRUD ────────────────────────────────────────────────────

@router.get("/appointments")
def list_appointments(
    current_user: dict     = Depends(get_current_user),
    db:           DbSession = Depends(get_read_db),
):
    pid = _require_patient(current_user)
    appts = (
        db.query(Appointment)
        .filter(Appointment.patient_id_hash == pid)
        .order_by(Appointment.appointment_date.desc(), Appointment.appointment_time.desc())
        .all()
    )
    result = []
    for a in appts:
        doctor_name = _resolve_doctor_name(db, a.doctor_id)
        dept = db.query(SyncDepartment).filter(
            SyncDepartment.department_code == a.department_code
        ).first()
        row = _appt_out(a, doctor_name)
        row["department_name"] = dept.department_name if dept else a.department_code
        result.append(row)
    return result


@router.get("/appointments/available-slots")
def get_available_slots(
    date:            str           = Query(..., description="조회 날짜 (YYYY-MM-DD)"),
    doctor_id:       Optional[str] = Query(default=None),
    department_code: Optional[str] = Query(default=None),
    current_user:    dict          = Depends(get_current_user),
    db:              DbSession     = Depends(get_read_db),
):
    """날짜·의사·진료과 기준 예약 가능 슬롯 조회 (09:00~17:30, 30분 간격)."""
    try:
        target_date = date_type.fromisoformat(date)
    except ValueError:
        raise HTTPException(status_code=422, detail="날짜 형식이 올바르지 않습니다. (YYYY-MM-DD)")

    if target_date < date_type.today():
        raise HTTPException(status_code=400, detail="과거 날짜는 조회할 수 없습니다.")

    all_slots = [
        time_type(h, m)
        for h in range(9, 18)
        for m in (0, 30)
        if not (h == 17 and m == 30)
    ]

    q = (
        db.query(Appointment.appointment_time)
        .join(AppointmentStatus, Appointment.status_id == AppointmentStatus.status_id)
        .filter(
            Appointment.appointment_date == target_date,
            ~AppointmentStatus.status_code.in_(["cancelled", "no_show"]),
        )
    )
    if doctor_id:
        try:
            q = q.filter(Appointment.doctor_id == uuid_module.UUID(doctor_id))
        except ValueError:
            raise HTTPException(status_code=422, detail="유효하지 않은 의사 ID입니다.")
    if department_code:
        q = q.filter(Appointment.department_code == department_code)

    booked = {row[0] for row in q.all()}

    return [
        {"time": t.strftime("%H:%M"), "available": t not in booked}
        for t in all_slots
    ]


@router.get("/appointments/{appointment_id}/history")
def get_appointment_history(
    appointment_id: str,
    current_user:   dict     = Depends(get_current_user),
    db:             DbSession = Depends(get_read_db),
):
    """예약 변경 이력 조회 (SFR-036)."""
    pid = _require_patient(current_user)
    try:
        appt_uuid = uuid_module.UUID(appointment_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="유효하지 않은 예약 ID입니다.")

    appt = db.query(Appointment).filter(
        Appointment.appointment_id  == appt_uuid,
        Appointment.patient_id_hash == pid,
    ).first()
    if not appt:
        raise HTTPException(status_code=404, detail="예약을 찾을 수 없습니다.")

    histories = (
        db.query(AppointmentHistory)
        .filter(AppointmentHistory.appointment_id == appt_uuid)
        .order_by(AppointmentHistory.changed_at.asc())
        .all()
    )

    def _status_name(status_id):
        if not status_id:
            return None
        s = db.query(AppointmentStatus).filter(AppointmentStatus.status_id == status_id).first()
        return s.status_name if s else None

    return [
        {
            "history_id":    str(h.history_id),
            "changed_at":    h.changed_at.isoformat() if h.changed_at else None,
            "prev_date":     str(h.prev_date) if h.prev_date else None,
            "new_date":      str(h.new_date)  if h.new_date  else None,
            "prev_time":     h.prev_time.strftime("%H:%M") if h.prev_time else None,
            "new_time":      h.new_time.strftime("%H:%M")  if h.new_time  else None,
            "prev_status":   _status_name(h.prev_status_id),
            "new_status":    _status_name(h.new_status_id),
            "change_reason": h.change_reason,
        }
        for h in histories
    ]


@router.get("/appointments/{appointment_id}")
def get_appointment(
    appointment_id: str,
    current_user: dict     = Depends(get_current_user),
    db:           DbSession = Depends(get_read_db),
):
    pid = _require_patient(current_user)
    try:
        appt_uuid = uuid_module.UUID(appointment_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="유효하지 않은 예약 ID입니다.")

    appt = db.query(Appointment).filter(
        Appointment.appointment_id  == appt_uuid,
        Appointment.patient_id_hash == pid,
    ).first()
    if not appt:
        raise HTTPException(status_code=404, detail="예약을 찾을 수 없습니다.")
    doctor_name = _resolve_doctor_name(db, appt.doctor_id)
    return _appt_out(appt, doctor_name)


@router.post("/appointments", status_code=201)
def create_appointment(
    body:         AppointmentCreateRequest,
    current_user: dict     = Depends(get_current_user),
    db:           DbSession = Depends(get_db),
):
    pid = _require_patient(current_user)
    now = datetime.now(timezone.utc)

    # 초진 예약 유형 차단 (SFR-035)
    if body.type_code.lower() in ("initial", "first_visit", "outpatient_new"):
        raise HTTPException(status_code=400, detail="초진 예약은 온라인으로 신청할 수 없습니다.")

    # 예약 유형 검증
    appt_type = db.query(AppointmentType).filter(
        AppointmentType.type_code == body.type_code,
        AppointmentType.is_active == True,
    ).first()
    if not appt_type:
        raise HTTPException(status_code=400, detail="유효하지 않은 예약 유형입니다.")

    # 재진·입원·수술: 해당 진료과 이전 내원 이력 필수
    if appt_type.requires_previous_visit:
        has_visit = db.query(SyncEncounter).filter(
            SyncEncounter.patient_id_hash == pid,
            SyncEncounter.department_code == body.department_code,
        ).first()
        if not has_visit:
            raise HTTPException(
                status_code=400,
                detail="해당 진료과의 이전 내원 이력이 없어 예약이 불가합니다.",
            )

    # 진료과 검증
    dept = db.query(SyncDepartment).filter(
        SyncDepartment.department_code == body.department_code,
        SyncDepartment.is_active == True,
    ).first()
    if not dept:
        raise HTTPException(status_code=400, detail="존재하지 않는 진료과입니다.")

    # 의사 검증 (선택)
    doctor_uuid = None
    if body.doctor_id:
        try:
            doctor_uuid = uuid_module.UUID(body.doctor_id)
        except ValueError:
            raise HTTPException(status_code=422, detail="유효하지 않은 의사 ID입니다.")
        doctor = db.query(SyncDoctor).filter(
            SyncDoctor.doctor_id       == doctor_uuid,
            SyncDoctor.department_code == body.department_code,
            SyncDoctor.is_active       == True,
        ).first()
        if not doctor:
            raise HTTPException(status_code=400, detail="해당 진료과에 소속된 의사가 아닙니다.")

    # 날짜·시간 파싱
    try:
        appt_date = date_type.fromisoformat(body.appointment_date)
    except ValueError:
        raise HTTPException(status_code=422, detail="날짜 형식이 올바르지 않습니다. (YYYY-MM-DD)")
    if appt_date < now.date():
        raise HTTPException(status_code=400, detail="과거 날짜로는 예약할 수 없습니다.")

    try:
        h, m = body.appointment_time.split(":")
        appt_time = time_type(int(h), int(m))
    except (ValueError, AttributeError):
        raise HTTPException(status_code=422, detail="시간 형식이 올바르지 않습니다. (HH:MM)")

    # 동시 요청 중복 예약 방지 (SFR-035) — 같은 의사·날짜·시간 행 잠금 후 재검증
    conflict_q = (
        db.query(Appointment)
        .join(AppointmentStatus, Appointment.status_id == AppointmentStatus.status_id)
        .filter(
            Appointment.appointment_date == appt_date,
            Appointment.appointment_time == appt_time,
            ~AppointmentStatus.status_code.in_(["cancelled", "no_show"]),
        )
        .with_for_update(nowait=False)
    )
    if doctor_uuid:
        conflict_q = conflict_q.filter(Appointment.doctor_id == doctor_uuid)
    else:
        conflict_q = conflict_q.filter(Appointment.department_code == body.department_code)
    if conflict_q.first():
        raise HTTPException(status_code=409, detail="선택한 시간대에 이미 예약이 있습니다. 다른 시간을 선택해주세요.")

    pending_status  = _get_pending_status(db)
    patient_user_id = uuid_module.UUID(current_user["sub"])

    import os
    # cloud RDS 는 patient_user_id NOT NULL — by 김다정, 2026-06-06
    appt_kwargs = dict(
        patient_id_hash       = pid,
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
        appt_kwargs["patient_user_id"] = patient_user_id
    appt = Appointment(**appt_kwargs)
    db.add(appt)
    db.flush()

    db.add(AppointmentHistory(
        appointment_id = appt.appointment_id,
        changed_by     = patient_user_id,
        new_status_id  = pending_status.status_id,
        new_date       = appt_date,
        new_time       = appt_time,
        change_reason  = "예약 신청",
    ))

    record_audit(
        db, action_type="APPOINTMENT_CREATE", result_code="201",
        user_id=patient_user_id, patient_id=pid,
        target_table="appointments", target_id=appt.appointment_id,
    )
    db.commit()
    db.refresh(appt)

    _notify_patient(db, appt, "pending")

    return _appt_out(appt)


@router.patch("/appointments/{appointment_id}")
def update_appointment(
    appointment_id: str,
    body:           AppointmentUpdateRequest,
    current_user:   dict     = Depends(get_current_user),
    db:             DbSession = Depends(get_db),
):
    pid = _require_patient(current_user)
    try:
        appt_uuid = uuid_module.UUID(appointment_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="유효하지 않은 예약 ID입니다.")

    appt = db.query(Appointment).filter(
        Appointment.appointment_id  == appt_uuid,
        Appointment.patient_id_hash == pid,
    ).first()
    if not appt:
        raise HTTPException(status_code=404, detail="예약을 찾을 수 없습니다.")

    # is_terminal인 예약(완료·취소)은 변경 불가 (SFR-036)
    if appt.appt_status and appt.appt_status.is_terminal:
        raise HTTPException(status_code=400, detail="완료되거나 취소된 예약은 변경할 수 없습니다.")

    now       = datetime.now(timezone.utc)
    prev_date = appt.appointment_date
    prev_time = appt.appointment_time

    if body.appointment_date is not None:
        try:
            new_date = date_type.fromisoformat(body.appointment_date)
        except ValueError:
            raise HTTPException(status_code=422, detail="날짜 형식이 올바르지 않습니다. (YYYY-MM-DD)")
        if new_date < now.date():
            raise HTTPException(status_code=400, detail="과거 날짜로는 변경할 수 없습니다.")
        appt.appointment_date = new_date

    if body.appointment_time is not None:
        try:
            h, m = body.appointment_time.split(":")
            appt.appointment_time = time_type(int(h), int(m))
        except (ValueError, AttributeError):
            raise HTTPException(status_code=422, detail="시간 형식이 올바르지 않습니다. (HH:MM)")

    if body.notes is not None:
        appt.notes = body.notes

    appt.updated_at = now
    patient_user_id = uuid_module.UUID(current_user["sub"])

    db.add(AppointmentHistory(
        appointment_id = appt.appointment_id,
        changed_by     = patient_user_id,
        prev_date      = prev_date,
        new_date       = appt.appointment_date,
        prev_time      = prev_time,
        new_time       = appt.appointment_time,
        change_reason  = "환자 일정 변경",
    ))

    record_audit(
        db, action_type="APPOINTMENT_UPDATE", result_code="200",
        user_id=patient_user_id, patient_id=pid,
        target_table="appointments", target_id=appt.appointment_id,
    )
    db.commit()
    db.refresh(appt)

    _notify_patient(
        db, appt, "updated",
        prev_date = str(prev_date),
        prev_time = prev_time.strftime("%H:%M") if prev_time else None,
    )

    return _appt_out(appt)


@router.delete("/appointments/{appointment_id}", status_code=200)
def cancel_appointment(
    appointment_id:    str,
    member_number:     Optional[str] = Query(default=None, description="본인 확인용 회원번호 (SFR-036)"),
    cancel_reason:     Optional[str] = Query(default=None),
    current_user:      dict     = Depends(get_current_user),
    db:                DbSession = Depends(get_db),
):
    pid = _require_patient(current_user)
    try:
        appt_uuid = uuid_module.UUID(appointment_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="유효하지 않은 예약 ID입니다.")

    # 본인 확인 절차 필수 (SFR-036)
    if not member_number:
        raise HTTPException(status_code=400, detail="예약 취소를 위해 회원번호를 입력해주세요.")

    user = db.query(User).filter(User.user_id == current_user["sub"]).first()
    if not user or user.member_number != member_number:
        raise HTTPException(status_code=403, detail="회원번호가 일치하지 않습니다. 본인 확인에 실패했습니다.")

    appt = db.query(Appointment).filter(
        Appointment.appointment_id  == appt_uuid,
        Appointment.patient_id_hash == pid,
    ).first()
    if not appt:
        raise HTTPException(status_code=404, detail="예약을 찾을 수 없습니다.")

    if appt.appt_status and appt.appt_status.is_terminal:
        raise HTTPException(status_code=400, detail="이미 완료되거나 취소된 예약입니다.")

    cancelled_status = db.query(AppointmentStatus).filter(
        AppointmentStatus.status_code == "cancelled"
    ).first()
    if not cancelled_status:
        raise HTTPException(status_code=500, detail="시스템 오류: 취소 상태 설정이 없습니다.")

    now             = datetime.now(timezone.utc)
    patient_user_id = uuid_module.UUID(current_user["sub"])

    db.add(AppointmentHistory(
        appointment_id = appt.appointment_id,
        changed_by     = patient_user_id,
        prev_status_id = appt.status_id,
        new_status_id  = cancelled_status.status_id,
        change_reason  = cancel_reason or "환자 취소",
    ))

    appt.status_id    = cancelled_status.status_id
    appt.cancelled_at = now
    appt.cancelled_by = patient_user_id
    appt.cancel_reason = cancel_reason
    appt.updated_at   = now

    record_audit(
        db, action_type="APPOINTMENT_CANCEL", result_code="200",
        user_id=patient_user_id, patient_id=pid,
        target_table="appointments", target_id=appt.appointment_id,
    )
    db.commit()
    db.refresh(appt)

    _notify_patient(db, appt, "cancelled")

    return {"message": "예약이 취소되었습니다.", "appointment": _appt_out(appt)}


# ── 개인정보 조회/수정 ────────────────────────────────────────────

class UpdateProfileRequest(BaseModel):
    email: EmailStr


@router.get("/my-profile")
def get_my_profile(
    current_user: dict     = Depends(get_current_user),
    db:           DbSession = Depends(get_read_db),
):
    """본인 이메일 + 비식별 인적정보 + 실명(onprem 조회) 반환."""
    user = db.query(User).filter(User.user_id == current_user["sub"]).first()
    result: dict = {"email": user.email, "patient_name": None}

    if user.patient_id_hash:
        patient = db.query(SyncPatient).filter(
            SyncPatient.patient_id_hash == user.patient_id_hash
        ).first()
        if patient:
            result["birth_year"]  = patient.birth_year
            result["gender_code"] = patient.gender_code

        # 환자 실명(patient_name)은 온프레미스에만 있음.
        # 브라우저가 병원 내부망에서 온프레미스 API를 직접 호출해야 합니다.
        # result["patient_name"] = None (기본값 유지)

    return result


@router.patch("/my-profile", status_code=200)
def update_my_profile(
    body:         UpdateProfileRequest,
    current_user: dict     = Depends(get_current_user),
    db:           DbSession = Depends(get_db),
):
    """이메일 변경."""
    user = db.query(User).filter(User.user_id == current_user["sub"]).first()

    if db.query(User).filter(
        User.email == body.email,
        User.user_id != user.user_id,
    ).first():
        raise HTTPException(status_code=400, detail="이미 사용 중인 이메일입니다.")

    user.email = body.email
    record_audit(
        db, action_type="UPDATE_PROFILE", result_code="200",
        user_id=uuid_module.UUID(current_user["sub"]),
        target_table="users",
    )
    db.commit()
    return {"email": user.email, "message": "이메일이 변경되었습니다."}


# ── 병동 조회 ─────────────────────────────────────────────────────

@router.get("/wards/availability")
def get_wards_availability(
    room_type:    Optional[str] = Query(default=None, description="single | double | shared"),
    current_user: dict          = Depends(get_current_user),
    db:           DbSession     = Depends(get_read_db),
):
    """가용 병상이 있는 병동 목록 조회 — 입원 예약 병동 선택용 (SFR-035)."""
    q = db.query(SyncWard).filter(SyncWard.available_beds > 0)
    if room_type:
        if room_type not in ("single", "double", "shared"):
            raise HTTPException(status_code=422, detail="room_type은 single | double | shared 중 하나여야 합니다.")
        q = q.filter(SyncWard.room_type == room_type)

    return [
        {
            "ward_id":        str(w.ward_id),
            "ward_name":      w.ward_name,
            "room_type":      w.room_type,
            "total_beds":     w.total_beds,
            "available_beds": w.available_beds,
        }
        for w in q.order_by(SyncWard.room_type, SyncWard.ward_name).all()
    ]


# ── 진료기록 조회 (SFR-037) ───────────────────────────────────────

@router.get("/my-records")
def get_my_records(
    current_user: dict     = Depends(get_current_user),
    db:           DbSession = Depends(get_db),
):
    """본인 진료기록 목록 조회 — diagnosis_text 미노출, 의사명 포함 (SFR-037)."""
    pid = current_user.get("pid")
    if not pid:
        raise HTTPException(status_code=403, detail="환자 계정만 진료기록을 조회할 수 있습니다.")

    encounters = (
        db.query(SyncEncounter)
        .filter(SyncEncounter.patient_id_hash == pid)
        .order_by(SyncEncounter.visit_date.desc())
        .all()
    )

    encounter_ids = [e.encounter_id for e in encounters]
    diagnoses = (
        db.query(SyncDiagnosis)
        .filter(SyncDiagnosis.encounter_id.in_(encounter_ids))
        .all()
    ) if encounter_ids else []

    diag_map: dict = {}
    for d in diagnoses:
        diag_map.setdefault(str(d.encounter_id), []).append(d.diagnosis_code)

    record_audit(
        db, action_type="EMR_SELF_VIEW", result_code="200",
        user_id=uuid_module.UUID(current_user["sub"]), patient_id_hash=pid,
        target_table="sync_encounters",
    )

    return [
        {
            "encounter_id":    str(e.encounter_id),
            "visit_date":      str(e.visit_date),
            "encounter_type":  e.encounter_type,
            "department_code": e.department_code,
            "doctor_id":       str(e.doctor_id) if e.doctor_id else None,
            "doctor_name":     _resolve_doctor_name(db, e.doctor_id),
            "status_code":     e.status_code,
            "diagnoses":       diag_map.get(str(e.encounter_id), []),
        }
        for e in encounters
    ]


@router.get("/encounters/{encounter_id}")
def get_encounter_detail(
    encounter_id: str,
    current_user: dict     = Depends(get_current_user),
    db:           DbSession = Depends(get_db),
):
    """진료 상세 조회 — diagnosis_text 미노출, clinical_notes 미제공 (SFR-037)."""
    pid = current_user.get("pid")
    if not pid:
        raise HTTPException(status_code=403, detail="환자 계정만 진료기록을 조회할 수 있습니다.")

    enc = db.query(SyncEncounter).filter(
        SyncEncounter.encounter_id == encounter_id
    ).first()

    if not enc:
        raise HTTPException(status_code=404, detail="진료 기록을 찾을 수 없습니다.")

    # 타 환자 접근 차단 + 감사 로그 (SFR-037)
    if enc.patient_id_hash != pid:
        record_audit(
            db, action_type="UNAUTHORIZED_ACCESS", result_code="403",
            user_id=uuid_module.UUID(current_user["sub"]), patient_id_hash=pid,
            target_table="sync_encounters",
        )
        db.commit()
        raise HTTPException(status_code=403, detail="본인의 진료 기록만 조회할 수 있습니다.")

    diagnoses = (
        db.query(SyncDiagnosis)
        .filter(SyncDiagnosis.encounter_id == encounter_id)
        .all()
    )

    dept = db.query(SyncDepartment).filter(
        SyncDepartment.department_code == enc.department_code
    ).first()

    record_audit(
        db, action_type="EMR_SELF_VIEW", result_code="200",
        user_id=uuid_module.UUID(current_user["sub"]), patient_id_hash=pid,
        target_table="sync_encounters",
    )
    db.commit()

    return {
        "encounter_id":    enc.encounter_id,
        "visit_date":      str(enc.visit_date),
        "encounter_type":  enc.encounter_type,
        "department_code": enc.department_code,
        "department_name": dept.department_name if dept else enc.department_code,
        "doctor_id":       str(enc.doctor_id) if enc.doctor_id else None,
        "doctor_name":     _resolve_doctor_name(db, enc.doctor_id),
        "status_code":     enc.status_code,
        "diagnoses":       [
            {
                "diagnosis_code": d.diagnosis_code,
                "is_primary":     d.is_primary,
            }
            for d in diagnoses
        ],
    }


@router.get("/allergies")
def get_allergies(
    current_user: dict     = Depends(get_current_user),
    db:           DbSession = Depends(get_read_db),
):
    """본인 알레르기 정보 조회 (SFR-037)."""
    pid = _require_patient(current_user)
    allergies = (
        db.query(SyncAllergy)
        .filter(SyncAllergy.patient_id_hash == pid)
        .all()
    )
    return [
        {
            "allergy_id":    a.allergy_id,
            "allergy_name":  a.allergy_name,
            "severity_code": a.severity_code,
        }
        for a in allergies
    ]


@router.get("/surgery-histories")
def get_surgery_histories(
    current_user: dict     = Depends(get_current_user),
    db:           DbSession = Depends(get_read_db),
):
    """본인 수술 이력 조회 (SFR-037)."""
    pid = _require_patient(current_user)
    surgeries = (
        db.query(SyncSurgery)
        .filter(SyncSurgery.patient_id_hash == pid)
        .order_by(SyncSurgery.surgery_date.desc())
        .all()
    )
    return [
        {
            "surgery_history_id": s.surgery_history_id,
            "surgery_name":       s.surgery_name,
            "surgery_date":       str(s.surgery_date) if s.surgery_date else None,
        }
        for s in surgeries
    ]


# ── 처방전 조회 (비식별: ICD 코드만 반환) ──────────────────────────
@router.get("/prescriptions")
def get_prescriptions(
    current_user: dict     = Depends(get_current_user),
    db:           DbSession = Depends(get_read_db),
):
    """본인 진단 코드 목록 조회 — diagnosis_code(ICD 코드)만, 원문 미포함 (SFR-037)."""
    pid = _require_patient(current_user)

    diagnoses = (
        db.query(SyncDiagnosis)
        .filter(SyncDiagnosis.patient_id_hash == pid)
        .order_by(SyncDiagnosis.diagnosed_at.desc())
        .all()
    )

    record_audit(
        db, action_type="VIEW_PRESCRIPTIONS", result_code="200",
        user_id=uuid_module.UUID(current_user["sub"]), patient_id_hash=pid,
        target_table="sync_diagnoses",
    )

    return [
        {
            "diagnosis_id":   str(d.diagnosis_id),
            "encounter_id":   str(d.encounter_id) if d.encounter_id else None,
            "diagnosis_code": d.diagnosis_code,
            "is_primary":     d.is_primary,
            "diagnosed_at":   d.diagnosed_at.isoformat() if d.diagnosed_at else None,
        }
        for d in diagnoses
    ]

