import uuid
from datetime import date as date_type, datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import func, or_
from sqlalchemy.orm import Session as DbSession

from core.database import get_db
from core.security import get_current_user
from models.db import (
    Appointment, AppointmentHistory, AppointmentStatus, AppointmentType,
    DB_MODE,
    OnpremAllergy, OnpremClinicalNote, OnpremDepartment, OnpremDiagnosis,
    OnpremDoctor, OnpremEncounter, OnpremSurgery, Patient,
    SyncAllergy, SyncDepartment, SyncDiagnosis, SyncDoctor, SyncEncounter,
    SyncPatient, SyncSurgery, SyncWard,
)

router = APIRouter(tags=["portal"])


class AppointmentCreate(BaseModel):
    department_code: str
    visit_hour: str  # ISO 8601 (e.g. "2025-03-15T10:00:00+09:00")


class AppointmentUpdate(BaseModel):
    department_code: Optional[str] = None
    visit_hour: Optional[str] = None  # ISO 8601


# ── 환자 포털 ────────────────────────────────────────────────

@router.get("/appointments")
def get_appointments(
    current_user: dict     = Depends(get_current_user),
    db:           DbSession = Depends(get_db),
):
    if current_user.get("role") != "patient":
        raise HTTPException(status_code=403, detail="권한이 없습니다.")

    pid = current_user.get("pid")
    if not pid:
        raise HTTPException(status_code=400, detail="연결된 환자 정보가 없습니다.")

    appts = (
        db.query(Appointment)
        .filter(Appointment.patient_id_hash == pid)
        .order_by(Appointment.appointment_date.desc(), Appointment.appointment_time.desc())
        .all()
    )

    dept_map   = {d.department_code: d.department_name for d in db.query(SyncDepartment).all()}
    doctor_map = {str(d.doctor_id): d.doctor_name for d in db.query(SyncDoctor).all()}

    return [
        {
            "appointment_id":   str(a.appointment_id),
            "appointment_date": str(a.appointment_date),
            "appointment_time": a.appointment_time.strftime("%H:%M") if a.appointment_time else None,
            "status_code":      a.appt_status.status_code  if a.appt_status else None,
            "status_name":      a.appt_status.status_name  if a.appt_status else None,
            "type_code":        a.appt_type.type_code      if a.appt_type   else None,
            "type_name":        a.appt_type.type_name      if a.appt_type   else None,
            "department_code":  a.department_code,
            "department_name":  dept_map.get(a.department_code),
            "doctor_name":      doctor_map.get(str(a.doctor_id)) if a.doctor_id else None,
            "notes":            a.notes,
        }
        for a in appts
    ]


@router.get("/appointments/{appointment_id}/history")
def get_appointment_history(
    appointment_id: str,
    current_user: dict     = Depends(get_current_user),
    db:           DbSession = Depends(get_db),
):
    if current_user.get("role") != "patient":
        raise HTTPException(status_code=403, detail="권한이 없습니다.")
    pid = current_user.get("pid")
    try:
        appt_uuid = uuid.UUID(appointment_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="유효하지 않은 예약 ID입니다.")
    appt = db.query(Appointment).filter(
        Appointment.appointment_id == appt_uuid,
        Appointment.patient_id_hash == pid,
    ).first()
    if not appt:
        raise HTTPException(status_code=404, detail="예약을 찾을 수 없습니다.")
    rows = db.query(AppointmentHistory).filter(
        AppointmentHistory.appointment_id == appt_uuid
    ).order_by(AppointmentHistory.changed_at.desc()).all()

    def _sname(sid):
        if not sid:
            return None
        s = db.query(AppointmentStatus).filter(AppointmentStatus.status_id == sid).first()
        return s.status_name if s else None

    return [{
        "prev_status":   _sname(r.prev_status_id),
        "new_status":    _sname(r.new_status_id),
        "prev_date":     str(r.prev_date)  if r.prev_date  else None,
        "new_date":      str(r.new_date)   if r.new_date   else None,
        "prev_time":     r.prev_time.strftime("%H:%M") if r.prev_time else None,
        "new_time":      r.new_time.strftime("%H:%M")  if r.new_time  else None,
        "change_reason": r.change_reason,
        "changed_at":    r.changed_at.isoformat() if r.changed_at else None,
    } for r in rows]


@router.get("/appointments/{encounter_id}")
def get_appointment_detail(
    encounter_id: str,
    current_user: dict     = Depends(get_current_user),
    db:           DbSession = Depends(get_db),
):
    if current_user.get("role") != "patient":
        raise HTTPException(status_code=403, detail="권한이 없습니다.")

    pid = current_user.get("pid")

    encounter = db.query(SyncEncounter).filter(
        SyncEncounter.encounter_id    == encounter_id,
        SyncEncounter.patient_id_hash == pid,
    ).first()

    if not encounter:
        raise HTTPException(status_code=404, detail="예약 정보를 찾을 수 없습니다.")

    return {
        "encounter_id":    str(encounter.encounter_id),
        "visit_date":      str(encounter.visit_date),
        "status_code":     encounter.status_code,
        "department_code": encounter.department_code,
        "synced_at":       str(encounter.synced_at),
    }


@router.post("/appointments", status_code=201)
def create_appointment(
    body:         AppointmentCreate,
    current_user: dict     = Depends(get_current_user),
    db:           DbSession = Depends(get_db),
):
    if current_user.get("role") != "patient":
        raise HTTPException(status_code=403, detail="환자만 예약할 수 있습니다.")

    pid = current_user.get("pid")
    if not pid:
        raise HTTPException(status_code=400, detail="연결된 환자 정보가 없습니다.")

    dept = db.query(SyncDepartment).filter(
        SyncDepartment.department_code == body.department_code,
        SyncDepartment.is_active == True,
    ).first()
    if not dept:
        raise HTTPException(status_code=400, detail="존재하지 않는 진료과입니다.")

    try:
        visit_dt   = datetime.fromisoformat(body.visit_hour)
        visit_date = visit_dt.date()
        visit_time = visit_dt.time()
    except ValueError:
        raise HTTPException(status_code=422, detail="날짜 형식이 올바르지 않습니다. (ISO 8601)")

    pending = db.query(AppointmentStatus).filter(AppointmentStatus.status_code == "pending").first()
    if not pending:
        pending = db.query(AppointmentStatus).order_by(AppointmentStatus.sort_order).first()
    if not pending:
        raise HTTPException(status_code=500, detail="예약 상태 코드가 설정되지 않았습니다.")

    appt_type = db.query(AppointmentType).filter(AppointmentType.is_active == True).order_by(AppointmentType.sort_order).first()

    now  = datetime.now(timezone.utc)
    appt_kwargs = dict(
        appointment_id   = uuid.uuid4(),
        patient_id_hash  = pid,
        type_id          = appt_type.type_id if appt_type else 1,
        status_id        = pending.status_id,
        department_code  = body.department_code,
        appointment_date = visit_date,
        appointment_time = visit_time,
        created_at       = now,
        updated_at       = now,
    )
    if DB_MODE == "cloud" and current_user.get("sub"):
        appt_kwargs["patient_user_id"] = uuid.UUID(current_user["sub"])
    appt = Appointment(**appt_kwargs)
    db.add(appt)
    db.commit()
    db.refresh(appt)

    return {
        "appointment_id":   str(appt.appointment_id),
        "appointment_date": str(appt.appointment_date),
        "appointment_time": appt.appointment_time.strftime("%H:%M") if appt.appointment_time else None,
        "status_code":      pending.status_code,
        "department_code":  appt.department_code,
    }


@router.patch("/appointments/{encounter_id}")
def update_appointment(
    encounter_id: str,
    body:         AppointmentUpdate,
    current_user: dict     = Depends(get_current_user),
    db:           DbSession = Depends(get_db),
):
    if current_user.get("role") != "patient":
        raise HTTPException(status_code=403, detail="환자만 예약을 수정할 수 있습니다.")

    pid = current_user.get("pid")

    try:
        appt_uuid = uuid.UUID(encounter_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="유효하지 않은 예약 ID입니다.")

    appt = db.query(Appointment).filter(
        Appointment.appointment_id  == appt_uuid,
        Appointment.patient_id_hash == pid,
    ).first()
    if not appt:
        raise HTTPException(status_code=404, detail="예약 정보를 찾을 수 없습니다.")
    if appt.appt_status and appt.appt_status.is_terminal:
        raise HTTPException(status_code=400, detail="완료되거나 취소된 예약은 수정할 수 없습니다.")

    if body.department_code is not None:
        dept = db.query(SyncDepartment).filter(
            SyncDepartment.department_code == body.department_code,
            SyncDepartment.is_active == True,
        ).first()
        if not dept:
            raise HTTPException(status_code=400, detail="존재하지 않는 진료과입니다.")
        appt.department_code = body.department_code

    if body.visit_hour is not None:
        try:
            visit_dt             = datetime.fromisoformat(body.visit_hour)
            appt.appointment_date = visit_dt.date()
            appt.appointment_time = visit_dt.time()
        except ValueError:
            raise HTTPException(status_code=422, detail="날짜 형식이 올바르지 않습니다. (ISO 8601)")

    appt.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(appt)

    return {
        "appointment_id":   str(appt.appointment_id),
        "appointment_date": str(appt.appointment_date),
        "appointment_time": appt.appointment_time.strftime("%H:%M") if appt.appointment_time else None,
        "status_code":      appt.appt_status.status_code if appt.appt_status else None,
        "department_code":  appt.department_code,
    }


@router.delete("/appointments/{encounter_id}")
def delete_appointment(
    encounter_id: str,
    current_user: dict     = Depends(get_current_user),
    db:           DbSession = Depends(get_db),
):
    if current_user.get("role") != "patient":
        raise HTTPException(status_code=403, detail="환자만 예약을 취소할 수 있습니다.")

    pid = current_user.get("pid")

    try:
        appt_uuid = uuid.UUID(encounter_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="유효하지 않은 예약 ID입니다.")

    appt = db.query(Appointment).filter(
        Appointment.appointment_id  == appt_uuid,
        Appointment.patient_id_hash == pid,
    ).first()
    if not appt:
        raise HTTPException(status_code=404, detail="예약 정보를 찾을 수 없습니다.")
    if appt.appt_status and appt.appt_status.is_terminal:
        raise HTTPException(status_code=400, detail="이미 완료되거나 취소된 예약입니다.")

    cancelled = db.query(AppointmentStatus).filter(AppointmentStatus.status_code == "cancelled").first()
    if cancelled:
        appt.status_id    = cancelled.status_id
        appt.cancelled_at = datetime.now(timezone.utc)
    db.commit()

    return {"message": "예약이 취소되었습니다."}


# ── 의사/간호사 포털 ─────────────────────────────────────────

@router.get("/departments")
def list_departments(
    current_user: dict     = Depends(get_current_user),
    db:           DbSession = Depends(get_db),
):
    if current_user.get("role") not in ("doctor", "nurse", "admin"):
        raise HTTPException(status_code=403, detail="권한이 없습니다.")
    depts = db.query(OnpremDepartment).filter(OnpremDepartment.is_active == True).all()
    return [
        {"department_code": d.department_code, "department_name": d.department_name}
        for d in depts
    ]


@router.get("/staff/appointments")
def list_staff_appointments(
    appt_date:   Optional[date_type] = None,
    status_code: Optional[str]       = None,
    current_user: dict               = Depends(get_current_user),
    db:           DbSession          = Depends(get_db),
):
    if current_user.get("role") not in ("doctor", "nurse", "admin"):
        raise HTTPException(status_code=403, detail="권한이 없습니다.")

    query = db.query(Appointment)
    if appt_date:
        query = query.filter(Appointment.appointment_date == appt_date)
    if status_code:
        query = query.join(AppointmentStatus).filter(AppointmentStatus.status_code == status_code)

    appts = query.order_by(Appointment.appointment_date.asc(), Appointment.appointment_time.asc()).all()

    return [
        {
            "appointment_id":        str(a.appointment_id),
            "patient_id_hash":       a.patient_id_hash,
            "type_code":             a.appt_type.type_code   if a.appt_type   else None,
            "type_name":             a.appt_type.type_name   if a.appt_type   else None,
            "status_code":           a.appt_status.status_code if a.appt_status else None,
            "status_name":           a.appt_status.status_name if a.appt_status else None,
            "appointment_date":      str(a.appointment_date),
            "appointment_time":      a.appointment_time.strftime("%H:%M") if a.appointment_time else None,
            "department_code":       a.department_code,
            "doctor_id":             str(a.doctor_id) if a.doctor_id else None,
            "notes":                 a.notes,
            "confirmed_at":          a.confirmed_at.isoformat() if a.confirmed_at else None,
            "cancelled_at":          a.cancelled_at.isoformat() if a.cancelled_at else None,
            "cancel_reason":         a.cancel_reason,
        }
        for a in appts
    ]


@router.get("/appointment-types")
def list_appointment_types(
    current_user: dict     = Depends(get_current_user),
    db:           DbSession = Depends(get_db),
):
    if current_user.get("role") not in ("doctor", "nurse", "admin"):
        raise HTTPException(status_code=403, detail="권한이 없습니다.")
    types = db.query(AppointmentType).filter(AppointmentType.is_active == True).order_by(AppointmentType.sort_order).all()
    return [
        {"type_code": t.type_code, "type_name": t.type_name, "requires_previous_visit": t.requires_previous_visit}
        for t in types
    ]


class _StaffApptCreate(BaseModel):
    patient_id_hash: str
    type_code:       str
    department_code: str
    doctor_id:       Optional[str] = None
    appointment_date: str
    appointment_time: str
    notes:           Optional[str] = None
    room_type_pref:  Optional[str] = None


@router.post("/staff/appointments", status_code=201)
def create_staff_appointment(
    body:         _StaffApptCreate,
    current_user: dict     = Depends(get_current_user),
    db:           DbSession = Depends(get_db),
):
    if current_user.get("role") not in ("nurse", "admin"):
        raise HTTPException(status_code=403, detail="권한이 없습니다.")

    appt_type = db.query(AppointmentType).filter(AppointmentType.type_code == body.type_code).first()
    if not appt_type:
        raise HTTPException(status_code=400, detail="존재하지 않는 예약 유형입니다.")

    init_status = db.query(AppointmentStatus).filter(AppointmentStatus.status_code == "pending").first()
    if not init_status:
        init_status = db.query(AppointmentStatus).order_by(AppointmentStatus.sort_order).first()
    if not init_status:
        raise HTTPException(status_code=500, detail="예약 상태 코드가 설정되지 않았습니다.")

    from datetime import date as _date, time as _time
    appt = Appointment(
        appointment_id   = uuid.uuid4(),
        patient_id_hash  = body.patient_id_hash,
        type_id          = appt_type.type_id,
        status_id        = init_status.status_id,
        department_code  = body.department_code,
        doctor_id        = uuid.UUID(body.doctor_id) if body.doctor_id else None,
        appointment_date = _date.fromisoformat(body.appointment_date),
        appointment_time = _time.fromisoformat(body.appointment_time),
        notes            = body.notes,
        room_type_pref   = body.room_type_pref,
    )
    db.add(appt)
    db.commit()
    db.refresh(appt)
    return {
        "appointment_id":   str(appt.appointment_id),
        "patient_id_hash":  appt.patient_id_hash,
        "status_code":      init_status.status_code,
        "appointment_date": str(appt.appointment_date),
        "appointment_time": appt.appointment_time.strftime("%H:%M"),
    }


class _StatusUpdate(BaseModel):
    status_code: str
    reason:      Optional[str] = None


@router.patch("/staff/appointments/{appointment_id}/status")
def update_staff_appointment_status(
    appointment_id: uuid.UUID,
    body:           _StatusUpdate,
    current_user:   dict     = Depends(get_current_user),
    db:             DbSession = Depends(get_db),
):
    if current_user.get("role") not in ("nurse", "admin"):
        raise HTTPException(status_code=403, detail="권한이 없습니다.")

    appt = db.query(Appointment).filter(Appointment.appointment_id == appointment_id).first()
    if not appt:
        raise HTTPException(status_code=404, detail="예약을 찾을 수 없습니다.")

    new_status = db.query(AppointmentStatus).filter(AppointmentStatus.status_code == body.status_code).first()
    if not new_status:
        raise HTTPException(status_code=400, detail="존재하지 않는 상태 코드입니다.")

    now = datetime.now(timezone.utc)
    history = AppointmentHistory(
        appointment_id = appt.appointment_id,
        changed_by     = uuid.UUID(current_user["sub"]),
        prev_status_id = appt.status_id,
        new_status_id  = new_status.status_id,
        change_reason  = body.reason,
        changed_at     = now,
    )
    appt.status_id = new_status.status_id
    if body.status_code == "confirmed":
        appt.confirmed_at = now
        appt.confirmed_by = uuid.UUID(current_user["sub"])
    elif body.status_code in ("cancelled", "no_show"):
        appt.cancelled_at    = now
        appt.cancelled_by    = uuid.UUID(current_user["sub"])
        appt.cancel_reason   = body.reason

    db.add(history)
    db.commit()
    return {"appointment_id": str(appt.appointment_id), "status_code": body.status_code}


@router.get("/staff/appointments/{appointment_id}/history")
def get_staff_appointment_history(
    appointment_id: uuid.UUID,
    current_user:   dict     = Depends(get_current_user),
    db:             DbSession = Depends(get_db),
):
    if current_user.get("role") not in ("doctor", "nurse", "admin"):
        raise HTTPException(status_code=403, detail="권한이 없습니다.")

    rows = db.query(AppointmentHistory).filter(
        AppointmentHistory.appointment_id == appointment_id
    ).order_by(AppointmentHistory.changed_at.desc()).all()

    def _status_code(status_id):
        if not status_id:
            return None
        s = db.query(AppointmentStatus).filter(AppointmentStatus.status_id == status_id).first()
        return s.status_code if s else None

    return [
        {
            "prev_status_code": _status_code(r.prev_status_id),
            "new_status_code":  _status_code(r.new_status_id),
            "change_reason":    r.change_reason,
            "changed_at":       r.changed_at.isoformat() if r.changed_at else None,
        }
        for r in rows
    ]


@router.get("/doctor/schedule")
def get_doctor_schedule(
    current_user: dict     = Depends(get_current_user),
    db:           DbSession = Depends(get_db),
):
    if current_user.get("role") not in ("doctor", "nurse", "admin"):
        raise HTTPException(status_code=403, detail="권한이 없습니다.")

    doctor_id = current_user.get("did")

    query = db.query(SyncEncounter)
    if doctor_id:
        query = query.filter(SyncEncounter.doctor_id == doctor_id)

    encounters = query.order_by(SyncEncounter.visit_date.desc()).all()

    return [
        {
            "encounter_id":    str(e.encounter_id),
            "patient_id_hash": e.patient_id_hash,
            "visit_date":      str(e.visit_date),
            "status_code":     e.status_code,
            "department_code": e.department_code,
            "synced_at":       str(e.synced_at),
        }
        for e in encounters
    ]



@router.get("/doctor/patients")
def get_doctor_patients(
    current_user: dict     = Depends(get_current_user),
    db:           DbSession = Depends(get_db),
):
    if current_user.get("role") not in ("doctor", "nurse", "admin"):
        raise HTTPException(status_code=403, detail="권한이 없습니다.")

    doctor_id = current_user.get("did")

    query = (
        db.query(
            SyncPatient.patient_id_hash,
            SyncPatient.birth_year,
            SyncPatient.gender_code,
            func.max(SyncEncounter.visit_date).label("last_visit"),
        )
        .outerjoin(SyncEncounter, SyncEncounter.patient_id_hash == SyncPatient.patient_id_hash)
    )

    if doctor_id:
        query = query.filter(SyncEncounter.doctor_id == doctor_id)

    results = query.group_by(
        SyncPatient.patient_id_hash,
        SyncPatient.birth_year,
        SyncPatient.gender_code,
    ).all()

    return [
        {
            "patient_id_hash": r.patient_id_hash,
            "birth_year":      r.birth_year,
            "gender_code":     r.gender_code,
            "last_visit":      str(r.last_visit) if r.last_visit else None,
        }
        for r in results
    ]


@router.get("/doctor/patients/{patient_id_hash}")
def get_doctor_patient_detail(
    patient_id_hash: str,
    current_user:    dict     = Depends(get_current_user),
    db:              DbSession = Depends(get_db),
):
    if current_user.get("role") not in ("doctor", "nurse", "admin"):
        raise HTTPException(status_code=403, detail="권한이 없습니다.")

    patient = db.query(SyncPatient).filter(
        SyncPatient.patient_id_hash == patient_id_hash
    ).first()
    if not patient:
        raise HTTPException(status_code=404, detail="환자 정보를 찾을 수 없습니다.")

    encounters = (
        db.query(SyncEncounter)
        .filter(SyncEncounter.patient_id_hash == patient_id_hash)
        .order_by(SyncEncounter.visit_date.desc())
        .all()
    )
    diagnoses = db.query(SyncDiagnosis).filter(SyncDiagnosis.patient_id_hash == patient_id_hash).all()
    allergies = db.query(SyncAllergy).filter(SyncAllergy.patient_id_hash == patient_id_hash).all()
    surgeries = db.query(SyncSurgery).filter(SyncSurgery.patient_id_hash == patient_id_hash).all()

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
                "status_code":     e.status_code,
                "department_code": e.department_code,
            }
            for e in encounters
        ],
        "diagnoses": [
            {"diagnosis_code": d.diagnosis_code, "is_primary": d.is_primary, "synced_at": str(d.synced_at)}
            for d in diagnoses
        ],
        "allergies": [
            {"allergy_name": a.allergy_name, "severity_code": a.severity_code}
            for a in allergies
        ],
        "surgeries": [
            {"surgery_name": s.surgery_name, "surgery_date": str(s.surgery_date)}
            for s in surgeries
        ],
    }


# ── 온프레미스 전용 — 의사/병동/환자 목록 ─────────────────────────────

@router.get("/doctors")
def list_doctors(
    department_code: Optional[str] = None,
    current_user:    dict          = Depends(get_current_user),
    db:              DbSession     = Depends(get_db),
):
    if current_user.get("role") not in ("doctor", "nurse", "admin"):
        raise HTTPException(status_code=403, detail="권한이 없습니다.")
    query = db.query(OnpremDoctor).filter(OnpremDoctor.is_active == True)
    if department_code:
        query = query.filter(OnpremDoctor.department_code == department_code)
    return [
        {"doctor_id": str(d.doctor_id), "doctor_name": d.doctor_name, "department_code": d.department_code}
        for d in query.all()
    ]


@router.get("/wards")
def list_wards(
    current_user: dict     = Depends(get_current_user),
    db:           DbSession = Depends(get_db),
):
    if current_user.get("role") not in ("doctor", "nurse", "admin"):
        raise HTTPException(status_code=403, detail="권한이 없습니다.")
    wards = db.query(SyncWard).all()
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


class _HashListBody(BaseModel):
    hashes: list[str]


@router.post("/patients/names-by-hashes")
def patients_names_by_hashes(
    body:         _HashListBody,
    current_user: dict     = Depends(get_current_user),
    db:           DbSession = Depends(get_db),
):
    if current_user.get("role") not in ("doctor", "nurse", "admin"):
        raise HTTPException(status_code=403, detail="권한이 없습니다.")
    patients = db.query(Patient).filter(Patient.patient_id_hash.in_(body.hashes)).all()
    return {p.patient_id_hash: p.patient_name for p in patients}


@router.get("/nurse/patients/search")
def nurse_search_patients(
    q:            str = None,
    limit:        int = 20,
    offset:       int = 0,
    current_user: dict     = Depends(get_current_user),
    db:           DbSession = Depends(get_db),
):
    if current_user.get("role") not in ("nurse", "admin"):
        raise HTTPException(status_code=403, detail="권한이 없습니다.")
    if not q:
        return []

    last_visit_sub = (
        db.query(
            OnpremEncounter.patient_id,
            func.max(OnpremEncounter.visit_datetime).label("last_visit"),
        )
        .group_by(OnpremEncounter.patient_id)
        .subquery()
    )

    base_q = (
        db.query(Patient, last_visit_sub.c.last_visit)
        .outerjoin(last_visit_sub, Patient.patient_id == last_visit_sub.c.patient_id)
        .filter(or_(
            Patient.patient_name.ilike(f"%{q}%"),
            Patient.member_number.ilike(f"%{q}%"),
        ))
    )
    total = base_q.count()
    rows = base_q.order_by(Patient.patient_name).offset(offset).limit(limit).all()
    return {
        "total": total,
        "items": [
            {
                "patient_id":      p.patient_id_hash,
                "patient_id_hash": p.patient_id_hash,
                "patient_name":    p.patient_name,
                "birth_date":      str(p.birth_date) if p.birth_date else None,
                "gender_code":     p.gender_code,
                "member_number":   p.member_number,
                "last_visit":      last_visit.isoformat() if last_visit else None,
            }
            for p, last_visit in rows
        ],
    }


# ── 환자 상세 (온프레미스 원본 테이블) ────────────────────────────────

def _get_patient_by_hash(db: DbSession, patient_id_hash: str) -> Patient:
    patient = db.query(Patient).filter(Patient.patient_id_hash == patient_id_hash).first()
    if not patient:
        raise HTTPException(status_code=404, detail="환자를 찾을 수 없습니다.")
    return patient


@router.get("/patients/{patient_id_hash}")
def get_patient(
    patient_id_hash: str,
    current_user:    dict     = Depends(get_current_user),
    db:              DbSession = Depends(get_db),
):
    if current_user.get("role") not in ("doctor", "nurse", "admin"):
        raise HTTPException(status_code=403, detail="권한이 없습니다.")
    p = _get_patient_by_hash(db, patient_id_hash)
    return {
        "patient_id":      p.patient_id_hash,  # 프론트엔드 호환 (EMR 이동용)
        "patient_id_hash": p.patient_id_hash,
        "patient_name":    p.patient_name,
        "birth_date":      str(p.birth_date),
        "gender_code":     p.gender_code,
        "phone_number":    p.phone_number,
        "member_number":   p.member_number,
    }


@router.get("/patients/{patient_id_hash}/encounters")
def get_patient_encounters(
    patient_id_hash: str,
    current_user:    dict     = Depends(get_current_user),
    db:              DbSession = Depends(get_db),
):
    if current_user.get("role") not in ("doctor", "nurse", "admin"):
        raise HTTPException(status_code=403, detail="권한이 없습니다.")
    p = _get_patient_by_hash(db, patient_id_hash)
    rows = db.query(OnpremEncounter).filter(
        OnpremEncounter.patient_id == p.patient_id
    ).order_by(OnpremEncounter.visit_datetime.desc()).all()
    return [
        {
            "encounter_id":    str(r.encounter_id),
            "encounter_type":  r.encounter_type,
            "department_code": r.department_code,
            "doctor_id":       str(r.doctor_id) if r.doctor_id else None,
            "visit_datetime":  r.visit_datetime.isoformat() if r.visit_datetime else None,
            "chief_complaint": r.chief_complaint,
            "status_code":     r.status_code,
        }
        for r in rows
    ]


@router.get("/patients/{patient_id_hash}/diagnoses")
def get_patient_diagnoses(
    patient_id_hash: str,
    current_user:    dict     = Depends(get_current_user),
    db:              DbSession = Depends(get_db),
):
    if current_user.get("role") not in ("doctor", "nurse", "admin"):
        raise HTTPException(status_code=403, detail="권한이 없습니다.")
    p = _get_patient_by_hash(db, patient_id_hash)
    rows = db.query(OnpremDiagnosis).filter(
        OnpremDiagnosis.patient_id == p.patient_id
    ).order_by(OnpremDiagnosis.diagnosed_at.desc()).all()
    return [
        {
            "diagnosis_code": r.diagnosis_code,
            "diagnosis_text": r.diagnosis_text,
            "is_primary":     r.is_primary,
            "diagnosed_at":   r.diagnosed_at.isoformat() if r.diagnosed_at else None,
        }
        for r in rows
    ]


@router.get("/patients/{patient_id_hash}/allergies")
def get_patient_allergies(
    patient_id_hash: str,
    current_user:    dict     = Depends(get_current_user),
    db:              DbSession = Depends(get_db),
):
    if current_user.get("role") not in ("doctor", "nurse", "admin"):
        raise HTTPException(status_code=403, detail="권한이 없습니다.")
    p = _get_patient_by_hash(db, patient_id_hash)
    rows = db.query(OnpremAllergy).filter(
        OnpremAllergy.patient_id == p.patient_id,
        OnpremAllergy.is_active == True,
    ).all()
    return [
        {"allergy_name": r.allergy_name, "severity_code": r.severity_code}
        for r in rows
    ]


@router.get("/patients/{patient_id_hash}/surgery-histories")
def get_patient_surgeries(
    patient_id_hash: str,
    current_user:    dict     = Depends(get_current_user),
    db:              DbSession = Depends(get_db),
):
    if current_user.get("role") not in ("doctor", "nurse", "admin"):
        raise HTTPException(status_code=403, detail="권한이 없습니다.")
    p = _get_patient_by_hash(db, patient_id_hash)
    rows = db.query(OnpremSurgery).filter(
        OnpremSurgery.patient_id == p.patient_id
    ).order_by(OnpremSurgery.surgery_date.desc()).all()
    return [
        {
            "surgery_name": r.surgery_name,
            "surgery_date": str(r.surgery_date) if r.surgery_date else None,
            "note":         r.note,
        }
        for r in rows
    ]


@router.get("/patients/{patient_id_hash}/verify")
def verify_patient(
    patient_id_hash: str,
    current_user:    dict     = Depends(get_current_user),
    db:              DbSession = Depends(get_db),
):
    if current_user.get("role") not in ("nurse", "admin"):
        raise HTTPException(status_code=403, detail="권한이 없습니다.")
    p = _get_patient_by_hash(db, patient_id_hash)
    return {
        "member_number": p.member_number,
        "birth_date":    str(p.birth_date),
    }
