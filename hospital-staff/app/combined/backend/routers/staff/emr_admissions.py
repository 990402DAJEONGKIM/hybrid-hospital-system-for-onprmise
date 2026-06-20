"""입원/퇴원 관리 라우터 (온프레미스 전용).

간호사: 입원 예약 승인, 현재 입원 환자 목록, 퇴원 처리
의사  : 담당 입원 환자 조회, 퇴원 지시 (온프레미스+RDS 이중 쓰기)
"""

import logging
import uuid
from datetime import date as date_type, datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import or_, text
from sqlalchemy.orm import Session as DbSession

from core.database import get_db, get_breakglass_db, get_rds_db
from core.security import get_current_user, record_audit
from models.db import (
    Admission, Appointment, AppointmentHistory, AppointmentStatus, AppointmentType,
    Bed, Patient as OnpremPatient, SyncDepartment, SyncWard,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/emr", tags=["admissions"])

_ACTIVE_STATUSES = ("ADMITTED", "DISCHARGE_ORDERED")


# ── 역할 헬퍼 ────────────────────────────────────────────────────

def _require_nurse(current_user: dict = Depends(get_current_user)) -> dict:
    if current_user.get("role") not in ("nurse", "admin"):
        raise HTTPException(status_code=403, detail="간호사 권한이 필요합니다.")
    return current_user


def _require_doctor(current_user: dict = Depends(get_current_user)) -> dict:
    if current_user.get("role") not in ("doctor", "admin"):
        raise HTTPException(status_code=403, detail="의사 권한이 필요합니다.")
    return current_user


# ── 환자 이름 일괄 조회 (breakglass: RLS 우회) ───────────────────

def _patient_name_map(hashes: list[str], bg_db: DbSession) -> dict[str, str]:
    if not hashes:
        return {}
    patients = (
        bg_db.query(OnpremPatient)
        .filter(OnpremPatient.patient_id_hash.in_(hashes))
        .all()
    )
    return {p.patient_id_hash: p.patient_name for p in patients}


# ── 병동·병상 자동 배정 ──────────────────────────────────────────

def _assign_ward_and_bed(
    db: DbSession,
    department_code: Optional[str],
    room_type_pref: Optional[str],
) -> tuple[SyncWard, Bed]:
    """부서코드 + 병실유형으로 병동·병상 자동 선택.

    available_beds = 0 이면 HTTPException 400.
    """
    ward_q = db.query(SyncWard).filter(SyncWard.available_beds > 0)
    if department_code:
        ward_q = ward_q.filter(SyncWard.department_code == department_code)
    if room_type_pref:
        ward_q = ward_q.filter(SyncWard.room_type == room_type_pref)

    ward = ward_q.first()
    if not ward:
        dept_msg = f" ({department_code})" if department_code else ""
        type_msg = f" {room_type_pref}실" if room_type_pref else ""
        raise HTTPException(
            status_code=400,
            detail=f"가용 병상이 없습니다{dept_msg}{type_msg}. 병동 현황을 확인하세요.",
        )

    bed = (
        db.query(Bed)
        .filter(Bed.ward_id == ward.ward_id, Bed.status == "AVAILABLE")
        .order_by(Bed.room_number.asc())
        .first()
    )
    if not bed:
        raise HTTPException(
            status_code=400,
            detail=f"병동({ward.ward_name})에 배정 가능한 병상이 없습니다.",
        )

    return ward, bed


def _admission_out(adm: Admission, ward: SyncWard, bed: Bed, patient_name: str) -> dict:
    return {
        "admission_id":            str(adm.admission_id),
        "patient_id_hash":         adm.patient_id_hash,
        "patient_name":            patient_name,
        "ward_id":                 str(adm.ward_id) if adm.ward_id else None,
        "ward_name":               ward.ward_name if ward else None,
        "department_code":         ward.department_code if ward else None,
        "bed_id":                  str(adm.bed_id) if adm.bed_id else None,
        "room_number":             bed.room_number if bed else None,
        "room_type":               adm.room_type,
        "status":                  adm.status,
        "admitted_at":             adm.admitted_at.isoformat() if adm.admitted_at else None,
        "expected_discharge_date": str(adm.expected_discharge_date) if adm.expected_discharge_date else None,
        "discharged_at":           adm.discharged_at.isoformat() if adm.discharged_at else None,
        "notes":                   adm.notes,
    }


# ============================================================
# 간호사 — 입원 승인 대기 목록
# ============================================================

@router.get("/nurse/admissions/pending")
def nurse_pending_appointments(
    request:      Request,
    current_user: dict      = Depends(_require_nurse),
    db:           DbSession = Depends(get_db),
    bg_db:        DbSession = Depends(get_breakglass_db),
):
    """인patient(입원) 예약 중 승인 대기(pending) 목록.

    appointments.type_code = 'inpatient' AND status = 'pending' 이고
    아직 admissions 레코드가 없는 건만 반환합니다.
    """
    inpatient_type = (
        db.query(AppointmentType)
        .filter(AppointmentType.type_code == "inpatient")
        .first()
    )
    if not inpatient_type:
        return []

    pending_status = (
        db.query(AppointmentStatus)
        .filter(AppointmentStatus.status_code == "pending")
        .first()
    )
    if not pending_status:
        return []

    # 아직 admissions에 없는 appointment만
    already_admitted_subq = db.query(Admission.appointment_id).subquery()
    appts = (
        db.query(Appointment)
        .filter(
            Appointment.type_id   == inpatient_type.type_id,
            Appointment.status_id == pending_status.status_id,
            Appointment.appointment_id.notin_(already_admitted_subq),
        )
        .order_by(Appointment.appointment_date.asc(), Appointment.appointment_time.asc())
        .all()
    )

    # 환자 이름 일괄 조회
    hashes = list({a.patient_id_hash for a in appts if a.patient_id_hash})
    name_map = _patient_name_map(hashes, bg_db)

    # 병동 가용 여부 미리 조회 (진료과별)
    dept_codes = {a.department_code for a in appts if a.department_code}
    ward_avail: dict[str, bool] = {}
    for dept_code in dept_codes:
        ward_avail[dept_code] = (
            db.query(SyncWard)
            .filter(
                SyncWard.department_code == dept_code,
                SyncWard.available_beds > 0,
            )
            .first()
        ) is not None

    result = [
        {
            "appointment_id":   str(a.appointment_id),
            "patient_id_hash":  a.patient_id_hash,
            "patient_name":     name_map.get(a.patient_id_hash, "—"),
            "appointment_date": str(a.appointment_date),
            "appointment_time": a.appointment_time.strftime("%H:%M") if a.appointment_time else None,
            "department_code":  a.department_code,
            "room_type_pref":   a.room_type_pref,
            "notes":            a.notes,
            "ward_available":   ward_avail.get(a.department_code, False),
        }
        for a in appts
    ]
    record_audit(
        db,
        action_type  = "VIEW_PENDING_ADMISSIONS",
        result_code  = "200",
        user_id      = current_user["sub"],
        target_table = "admissions",
        source_ip    = request.client.host if request.client else None,
    )
    db.commit()
    return result


# ============================================================
# 간호사 — 입원 승인 처리
# ============================================================

class AdmitRequest(BaseModel):
    appointment_id:          str
    expected_discharge_date: Optional[str] = None   # YYYY-MM-DD
    notes:                   Optional[str] = None


@router.post("/nurse/admissions", status_code=201)
def nurse_admit_patient(
    body:         AdmitRequest,
    request:      Request,
    current_user: dict      = Depends(_require_nurse),
    db:           DbSession = Depends(get_db),
):
    """입원 예약 승인.

    1. appointments.status → confirmed
    2. 병동·병상 자동 배정
    3. admissions INSERT (status=ADMITTED)
    4. beds.status = OCCUPIED
    5. sync_wards.available_beds - 1
    """
    try:
        appt_uuid = uuid.UUID(body.appointment_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="유효하지 않은 appointment_id 형식입니다.")

    appt = db.query(Appointment).filter(Appointment.appointment_id == appt_uuid).first()
    if not appt:
        raise HTTPException(status_code=404, detail="예약을 찾을 수 없습니다.")

    inpatient_type = (
        db.query(AppointmentType)
        .filter(AppointmentType.type_id == appt.type_id)
        .first()
    )
    if not inpatient_type or inpatient_type.type_code != "inpatient":
        raise HTTPException(status_code=400, detail="입원 예약이 아닙니다.")

    pending_status = (
        db.query(AppointmentStatus)
        .filter(AppointmentStatus.status_code == "pending")
        .first()
    )
    if not pending_status or appt.status_id != pending_status.status_id:
        raise HTTPException(status_code=400, detail="대기 상태의 예약만 승인할 수 있습니다.")

    # 이미 승인된 admission이 있는지 확인
    existing = (
        db.query(Admission)
        .filter(Admission.appointment_id == appt_uuid)
        .first()
    )
    if existing:
        raise HTTPException(status_code=409, detail="이미 입원 처리된 예약입니다.")

    # 병동·병상 자동 배정
    ward, bed = _assign_ward_and_bed(db, appt.department_code, appt.room_type_pref)

    # expected_discharge_date 파싱
    exp_date = None
    if body.expected_discharge_date:
        try:
            exp_date = date_type.fromisoformat(body.expected_discharge_date)
        except ValueError:
            raise HTTPException(status_code=422, detail="퇴원 예정일 형식이 올바르지 않습니다 (YYYY-MM-DD).")

    now = datetime.now(timezone.utc)
    nurse_user_id = uuid.UUID(current_user["sub"])

    # ── appointments → confirmed ──────────────────────────────
    confirmed_status = (
        db.query(AppointmentStatus)
        .filter(AppointmentStatus.status_code == "confirmed")
        .first()
    )
    prev_status_id = appt.status_id
    if confirmed_status:
        appt.status_id    = confirmed_status.status_id
        appt.confirmed_at = now
        appt.confirmed_by = nurse_user_id
        appt.updated_at   = now
        db.add(AppointmentHistory(
            appointment_id = appt.appointment_id,
            changed_by     = nurse_user_id,
            prev_status_id = prev_status_id,
            new_status_id  = confirmed_status.status_id,
            change_reason  = "입원 승인",
            changed_at     = now,
        ))

    # ── admissions INSERT ────────────────────────────────────
    admission = Admission(
        admission_id            = uuid.uuid4(),
        appointment_id          = appt_uuid,
        patient_id_hash         = appt.patient_id_hash,
        ward_id                 = ward.ward_id,
        bed_id                  = bed.bed_id,
        room_type               = ward.room_type,
        admitted_by             = nurse_user_id,
        admitted_at             = now,
        expected_discharge_date = exp_date,
        status                  = "ADMITTED",
        notes                   = body.notes,
        created_at              = now,
        updated_at              = now,
    )
    db.add(admission)

    # ── beds.status = OCCUPIED ───────────────────────────────
    bed.status     = "OCCUPIED"
    bed.updated_at = now

    # ── sync_wards.available_beds - 1 ───────────────────────
    ward.available_beds = max(0, (ward.available_beds or 0) - 1)
    ward.updated_at     = now

    response = {
        "admission_id":   str(admission.admission_id),
        "ward_name":      ward.ward_name,
        "room_number":    bed.room_number,
        "room_type":      ward.room_type,
        "status":         admission.status,
        "admitted_at":    admission.admitted_at.isoformat(),
    }
    record_audit(
        db,
        action_type  = "ADMIT_PATIENT",
        result_code  = "201",
        user_id      = current_user["sub"],
        target_table = "admissions",
        target_id    = admission.admission_id,
        source_ip    = request.client.host if request.client else None,
    )
    db.commit()
    return response


# ============================================================
# 간호사 — 현재 입원 환자 목록
# ============================================================

@router.get("/nurse/admissions/current")
def nurse_current_inpatients(
    request:      Request,
    current_user: dict      = Depends(_require_nurse),
    db:           DbSession = Depends(get_db),
    bg_db:        DbSession = Depends(get_breakglass_db),
):
    """현재 입원 환자 목록 (ADMITTED + DISCHARGE_ORDERED)."""
    admissions = (
        db.query(Admission)
        .filter(Admission.status.in_(_ACTIVE_STATUSES))
        .order_by(Admission.admitted_at.desc())
        .all()
    )

    hashes = list({a.patient_id_hash for a in admissions if a.patient_id_hash})
    name_map = _patient_name_map(hashes, bg_db)

    ward_ids = list({a.ward_id for a in admissions if a.ward_id})
    wards: dict[uuid.UUID, SyncWard] = {}
    if ward_ids:
        wards = {w.ward_id: w for w in db.query(SyncWard).filter(SyncWard.ward_id.in_(ward_ids)).all()}

    bed_ids = list({a.bed_id for a in admissions if a.bed_id})
    beds: dict[uuid.UUID, Bed] = {}
    if bed_ids:
        beds = {b.bed_id: b for b in db.query(Bed).filter(Bed.bed_id.in_(bed_ids)).all()}

    result = [
        _admission_out(
            adm,
            wards.get(adm.ward_id),
            beds.get(adm.bed_id),
            name_map.get(adm.patient_id_hash, "—"),
        )
        for adm in admissions
    ]
    record_audit(
        db,
        action_type  = "VIEW_CURRENT_INPATIENTS",
        result_code  = "200",
        user_id      = current_user["sub"],
        target_table = "admissions",
        source_ip    = request.client.host if request.client else None,
    )
    db.commit()
    return result


# ============================================================
# 간호사 — 퇴원 처리
# ============================================================

@router.patch("/nurse/admissions/{admission_id}/discharge")
def nurse_discharge_patient(
    admission_id: str,
    request:      Request,
    current_user: dict      = Depends(_require_nurse),
    db:           DbSession = Depends(get_db),
):
    """퇴원 처리.

    1. admissions.status = DISCHARGED, discharged_at = now()
    2. beds.status = AVAILABLE
    3. sync_wards.available_beds + 1
    """
    try:
        adm_uuid = uuid.UUID(admission_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="유효하지 않은 admission_id 형식입니다.")

    adm = db.query(Admission).filter(Admission.admission_id == adm_uuid).first()
    if not adm:
        raise HTTPException(status_code=404, detail="입원 기록을 찾을 수 없습니다.")

    if adm.status == "DISCHARGED":
        raise HTTPException(status_code=400, detail="이미 퇴원 처리된 환자입니다.")

    if adm.status not in _ACTIVE_STATUSES:
        raise HTTPException(status_code=400, detail="퇴원 처리할 수 없는 상태입니다.")

    now = datetime.now(timezone.utc)

    # ── admissions 업데이트 ──────────────────────────────────
    adm.status       = "DISCHARGED"
    adm.discharged_at = now
    adm.updated_at    = now

    # ── beds.status = AVAILABLE ──────────────────────────────
    if adm.bed_id:
        bed = db.query(Bed).filter(Bed.bed_id == adm.bed_id).first()
        if bed:
            bed.status     = "AVAILABLE"
            bed.updated_at = now

    # ── sync_wards.available_beds + 1 ───────────────────────
    if adm.ward_id:
        ward = db.query(SyncWard).filter(SyncWard.ward_id == adm.ward_id).first()
        if ward:
            ward.available_beds = min(
                ward.total_beds or 0,
                (ward.available_beds or 0) + 1,
            )
            ward.updated_at = now

    response = {"admission_id": str(adm.admission_id), "status": adm.status, "discharged_at": adm.discharged_at.isoformat()}
    record_audit(
        db,
        action_type  = "DISCHARGE_PATIENT",
        result_code  = "200",
        user_id      = current_user["sub"],
        target_table = "admissions",
        target_id    = adm_uuid,
        source_ip    = request.client.host if request.client else None,
    )
    db.commit()
    return response


# ============================================================
# 의사 — 담당 입원 환자 목록
# ============================================================

@router.get("/doctor/admissions")
def doctor_inpatients(
    request:      Request,
    current_user: dict      = Depends(_require_doctor),
    db:           DbSession = Depends(get_db),
    bg_db:        DbSession = Depends(get_breakglass_db),
):
    """담당 의사 기준 현재 입원 환자 (ADMITTED + DISCHARGE_ORDERED)."""
    doctor_id = current_user.get("did")
    if not doctor_id:
        raise HTTPException(status_code=400, detail="의사 정보가 연결되지 않은 계정입니다.")

    try:
        doctor_uuid = uuid.UUID(str(doctor_id))
    except ValueError:
        raise HTTPException(status_code=400, detail="의사 ID 형식이 잘못되었습니다.")

    # admissions JOIN appointments WHERE appointments.doctor_id = doctor_uuid
    rows = (
        db.query(Admission, Appointment)
        .join(Appointment, Admission.appointment_id == Appointment.appointment_id)
        .filter(
            Appointment.doctor_id == doctor_uuid,
            Admission.status.in_(_ACTIVE_STATUSES),
        )
        .order_by(Admission.admitted_at.desc())
        .all()
    )
    admissions = [r[0] for r in rows]

    hashes = list({a.patient_id_hash for a in admissions if a.patient_id_hash})
    name_map = _patient_name_map(hashes, bg_db)

    ward_ids = list({a.ward_id for a in admissions if a.ward_id})
    wards: dict[uuid.UUID, SyncWard] = {}
    if ward_ids:
        wards = {w.ward_id: w for w in db.query(SyncWard).filter(SyncWard.ward_id.in_(ward_ids)).all()}

    bed_ids = list({a.bed_id for a in admissions if a.bed_id})
    beds: dict[uuid.UUID, Bed] = {}
    if bed_ids:
        beds = {b.bed_id: b for b in db.query(Bed).filter(Bed.bed_id.in_(bed_ids)).all()}

    result = [
        _admission_out(
            adm,
            wards.get(adm.ward_id),
            beds.get(adm.bed_id),
            name_map.get(adm.patient_id_hash, "—"),
        )
        for adm in admissions
    ]
    record_audit(
        db,
        action_type  = "VIEW_DOCTOR_INPATIENTS",
        result_code  = "200",
        user_id      = current_user["sub"],
        target_table = "admissions",
        source_ip    = request.client.host if request.client else None,
    )
    db.commit()
    return result


# ============================================================
# 의사 — 퇴원 지시 (온프레미스 + RDS 이중 쓰기)
# ============================================================

@router.patch("/doctor/admissions/{admission_id}/order-discharge")
def doctor_order_discharge(
    admission_id: str,
    request:      Request,
    current_user: dict               = Depends(_require_doctor),
    db:           DbSession          = Depends(get_db),
    rds_db:       Optional[DbSession] = Depends(get_rds_db),
):
    """퇴원 지시.

    온프레미스 admissions.status = DISCHARGE_ORDERED 업데이트 후
    RDS가 설정된 경우 동일한 행을 RDS에도 반영합니다.
    """
    try:
        adm_uuid = uuid.UUID(admission_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="유효하지 않은 admission_id 형식입니다.")

    adm = db.query(Admission).filter(Admission.admission_id == adm_uuid).first()
    if not adm:
        raise HTTPException(status_code=404, detail="입원 기록을 찾을 수 없습니다.")

    if adm.status != "ADMITTED":
        raise HTTPException(
            status_code=400,
            detail="입원(ADMITTED) 상태인 환자에게만 퇴원을 지시할 수 있습니다.",
        )

    now = datetime.now(timezone.utc)
    doctor_user_id = uuid.UUID(current_user["sub"])

    # ── 온프레미스 업데이트 ──────────────────────────────────
    adm.status                = "DISCHARGE_ORDERED"
    adm.discharge_ordered_by  = doctor_user_id
    adm.updated_at            = now

    response = {
        "admission_id":         str(adm.admission_id),
        "status":               adm.status,
        "discharge_ordered_by": str(adm.discharge_ordered_by),
        "updated_at":           adm.updated_at.isoformat(),
    }
    record_audit(
        db,
        action_type  = "ORDER_DISCHARGE",
        result_code  = "200",
        user_id      = current_user["sub"],
        target_table = "admissions",
        target_id    = adm_uuid,
        source_ip    = request.client.host if request.client else None,
    )
    db.commit()

    # ── RDS 이중 쓰기 ────────────────────────────────────────
    if rds_db is not None:
        try:
            rds_db.execute(
                text("""
                    UPDATE admissions
                    SET status = 'DISCHARGE_ORDERED',
                        discharge_ordered_by = :doctor_uid,
                        updated_at = :now
                    WHERE admission_id = :adm_id
                """),
                {
                    "doctor_uid": str(doctor_user_id),
                    "now":        now,
                    "adm_id":     str(adm_uuid),
                },
            )
            rds_db.commit()
        except Exception as exc:
            logger.warning("RDS 퇴원 지시 동기화 실패 (admission_id=%s): %s", adm_uuid, exc)
            try:
                rds_db.rollback()
            except Exception:
                pass

    return response
