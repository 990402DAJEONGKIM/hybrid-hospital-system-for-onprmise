"""SFR-018/019 — 의사 전용 EMR 라우터 (온프레미스 전용).

[데이터 등급] 1등급 개인정보 — 환자 실명, 진료노트, 진단명 포함
  - RDS/GCP 전송 절대 금지 (ISMS-P 2.3.1)
  - 온프레미스 DB에서 직접 조회
  - 모든 접근은 audit_logs에 기록 (ISMS-P 2.9.1)
"""

import logging
import uuid
from datetime import date as date_type, datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session as DbSession

from core.database import get_db, get_breakglass_db   # 260612 박경수: import 추가
from core.security import get_current_user, record_audit
from models.db import (
    AuditLog,
    Patient as OnpremPatient, OnpremEncounter, OnpremClinicalNote,
    OnpremDiagnosis, OnpremAllergy, OnpremSurgery,
    PatientEmrSummary,
    Appointment, AppointmentStatus, AppointmentHistory,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/emr/doctor", tags=["emr-doctor"])


def _require_doctor(current_user: dict = Depends(get_current_user)) -> dict:
    if current_user.get("role") not in ("doctor", "admin"):
        raise HTTPException(status_code=403, detail="의사 권한이 필요합니다.")
    return current_user


# 260612 박경수: RLS enforce 대응 — 공통 record_audit(log_audit 경유) 사용
def _record_audit(
    db: DbSession,
    user_id: str,
    action: str,
    result: str,
    request: Request,
    patient_id=None,
    target_table: str = "patients",
) -> None:
    from core.security import record_audit
    record_audit(
        db,
        action_type  = action,
        result_code  = result,
        user_id      = user_id,
        patient_id   = patient_id,
        target_table = target_table,
        source_ip    = request.client.host if request.client else None,
    )
    db.commit()

def _decode_note(n) -> dict:
    """PROGRESS 노트에 인코딩된 SOAP 타입([S]/[O]/[A]/[P])을 복원"""
    note_type = n.note_type
    note_text = n.note_text
    if n.note_type == 'PROGRESS':
        for soap in ('S', 'O', 'A', 'P'):
            prefix = f'[{soap}] '
            if n.note_text.startswith(prefix):
                note_type = soap
                note_text = n.note_text[len(prefix):]
                break
    return {
        "note_type":   note_type,
        "author_type": n.author_type,
        "note_text":   note_text,
        "created_at":  n.created_at.isoformat() if n.created_at else None,
    }

# ── SFR-018 담당 환자 목록 ────────────────────────────────────────

@router.get("/patients")
def doctor_list_patients(
    q:            Optional[str] = Query(default=None, description="환자명 검색"),
    sort:         Optional[str] = Query(default="patient_name"),
    tab:          Optional[str] = Query(default="outpatient"),
    limit:        int           = Query(default=50, le=200),
    offset:       int           = Query(default=0),
    request:      Request       = None,
    current_user: dict          = Depends(_require_doctor),
    db:           DbSession     = Depends(get_db),
):
    """담당 의사의 환자 목록 조회 — 온프레미스 1등급 데이터"""
    print("DEBUG current_user:", current_user, flush=True)
    doctor_id = current_user.get("did")
    if not doctor_id:
        raise HTTPException(status_code=400, detail="의사 정보가 연결되지 않은 계정입니다.")





    from sqlalchemy import text
    _SORT_MAP = {
        "patient_name": "p.patient_name",
        "last_visit":   "last_visit DESC NULLS LAST",
        "next_appt":    "next_appt ASC NULLS LAST",
    }
    order_clause = _SORT_MAP.get(sort, "p.patient_name")
    search_clause = "AND p.patient_name ILIKE :q" if q else ""
    params = {"doctor_id": str(doctor_id), "limit": limit, "offset": offset}
    if q:
        params["q"] = f"%{q}%"

    _VALID_ENC_TYPES = {'outpatient_new', 'outpatient_return', 'inpatient', 'pre_surgery'}
    if tab and tab in _VALID_ENC_TYPES:
        tab_clause = "AND e.encounter_type = :enc_type"
        params["enc_type"] = tab
    else:
        tab_clause = ""

    result = db.execute(text(f"""
        SELECT DISTINCT p.patient_id, p.patient_name, p.birth_date,
               p.gender_code, p.phone_number, p.member_number,
               (
                   SELECT MAX(e2.visit_datetime)
                   FROM encounters e2
                   WHERE e2.patient_id = p.patient_id
               ) AS last_visit,
               (
                   SELECT MIN(a.appointment_date)
                   FROM appointments a
                   WHERE a.patient_id_hash = p.patient_id_hash
                     AND a.appointment_date >= CURRENT_DATE
                     AND a.doctor_id = :doctor_id
               ) AS next_appt
        FROM patients p
        JOIN encounters e ON e.patient_id = p.patient_id
        WHERE e.doctor_id = :doctor_id {tab_clause} {search_clause}
        ORDER BY {order_clause}
        LIMIT :limit OFFSET :offset
    """), params)

    count_result = db.execute(text(f"""
        SELECT COUNT(DISTINCT p.patient_id)
        FROM patients p
        JOIN encounters e ON e.patient_id = p.patient_id
        WHERE e.doctor_id = :doctor_id {tab_clause} {search_clause}
    """), params)

    patients = result.fetchall()
    total = count_result.scalar()

    _record_audit(db, current_user["sub"], "VIEW_PATIENT_LIST", "200", request)

    return {
        "items": [
            {
                "patient_id":    str(p.patient_id),
                "patient_name":  p.patient_name,
                "birth_date":    str(p.birth_date),
                "gender_code":   p.gender_code,
                "phone_number":  p.phone_number,
                "member_number": p.member_number,
                "last_visit":    p.last_visit.strftime("%Y-%m-%d") if p.last_visit else None,
                "next_appt":     str(p.next_appt) if p.next_appt else None,
            }
            for p in patients
        ],
        "total": total
    }



@router.get("/patients/search")
def doctor_search_patients(
    q:            str     = Query(..., min_length=1),
    request:      Request = None,
    current_user: dict    = Depends(_require_doctor),
    db:           DbSession = Depends(get_db),
):
    """전체 환자 검색 (이름 또는 회원번호) — 온프레미스 1등급 데이터"""
    from sqlalchemy import or_, func
    last_visit_sub = (
        db.query(
            OnpremEncounter.patient_id,
            func.max(OnpremEncounter.visit_datetime).label("last_visit"),
        )
        .group_by(OnpremEncounter.patient_id)
        .subquery()
    )

    rows = (
        db.query(OnpremPatient, last_visit_sub.c.last_visit)
        .outerjoin(last_visit_sub, OnpremPatient.patient_id == last_visit_sub.c.patient_id)
        .filter(or_(
            OnpremPatient.patient_name.ilike(f"%{q}%"),
            OnpremPatient.member_number.ilike(f"%{q}%"),
        ))
        .limit(20)
        .all()
    )

    result = [
        {
            "patient_id":    str(p.patient_id),
            "patient_name":  p.patient_name,
            "birth_date":    str(p.birth_date),
            "gender_code":   p.gender_code,
            "member_number": p.member_number,
            "last_visit":    last_visit.isoformat() if last_visit else None,
        }
        for p, last_visit in rows
    ]
    _record_audit(db, current_user["sub"], "SEARCH_PATIENT", "200", request)
    return result


# ── SFR-019 환자 EMR 조회 ─────────────────────────────────────────

@router.get("/patients/{patient_id}/emr")
def doctor_get_emr(
    patient_id:   str,
    request:      Request,
    current_user: dict      = Depends(_require_doctor),
    db:           DbSession = Depends(get_db),
):
    """환자 전체 EMR 조회 (진료기록 + AI 요약) — 온프레미스 1등급 데이터"""
    try:
        pid = uuid.UUID(patient_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="유효하지 않은 patient_id 형식입니다.")

    patient = db.query(OnpremPatient).filter(OnpremPatient.patient_id == pid).first()
    if not patient:
        raise HTTPException(status_code=404, detail="환자를 찾을 수 없습니다.")

    encounters = (
        db.query(OnpremEncounter)
        .filter(OnpremEncounter.patient_id == pid)
        .order_by(OnpremEncounter.visit_datetime.desc())
        .all()
    )

    diagnoses = (
        db.query(OnpremDiagnosis)
        .filter(OnpremDiagnosis.patient_id == pid)
        .all()
    )

    allergies = (
        db.query(OnpremAllergy)
        .filter(OnpremAllergy.patient_id == pid)
        .all()
    )

    surgeries = (
        db.query(OnpremSurgery)
        .filter(OnpremSurgery.patient_id == pid)
        .all()
    )

    clinical_notes = (
        db.query(OnpremClinicalNote)
        .filter(OnpremClinicalNote.patient_id == pid)
        .order_by(OnpremClinicalNote.created_at.desc())
        .limit(20)
        .all()
    )

    # AI 요약 조회 (없으면 None)
    emr_summary = db.query(PatientEmrSummary).filter(
        PatientEmrSummary.patient_id == pid
    ).first()

    response = {
        "patient": {
            "patient_id":   str(patient.patient_id),
            "patient_name": patient.patient_name,
            "birth_date":   str(patient.birth_date),
            "gender_code":  patient.gender_code,
            "phone_number": patient.phone_number,
            "email":        patient.email,
        },
        "ai_summary": {
            "summary_text": emr_summary.summary_text if emr_summary else None,
            "generated_at": emr_summary.generated_at.isoformat() if emr_summary and emr_summary.generated_at else None,
        },
        "encounters": [
            {
                "encounter_id":    str(e.encounter_id),
                "encounter_type":  e.encounter_type,
                "department_code": e.department_code,
                "visit_datetime":  e.visit_datetime.isoformat() if e.visit_datetime else None,
                "chief_complaint": e.chief_complaint,
                "status_code":     e.status_code,
            }
            for e in encounters
        ],
        "diagnoses": [
            {
                "diagnosis_code": d.diagnosis_code,
                "diagnosis_text": d.diagnosis_text,
                "is_primary":     d.is_primary,
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
                "surgery_date": str(s.surgery_date) if s.surgery_date else None,
            }
            for s in surgeries
        ],
        "clinical_notes": [
            {
                "note_type":  n.note_type,
                "author_type": n.author_type,
                "note_text":  n.note_text,
                "created_at": n.created_at.isoformat() if n.created_at else None,
            }
            for n in clinical_notes
        ],
    }
    _record_audit(db, current_user["sub"], "VIEW_EMR", "200", request, pid)
    return response


@router.get("/patients/{patient_id}/encounters/latest")
def doctor_get_latest_encounter(
    patient_id:   str,
    request:      Request,
    current_user: dict      = Depends(_require_doctor),
    db:           DbSession = Depends(get_db),
):
    """최근 진료 encounter 조회"""
    try:
        pid = uuid.UUID(patient_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="유효하지 않은 patient_id 형식입니다.")

    encounter = (
        db.query(OnpremEncounter)
        .filter(OnpremEncounter.patient_id == pid)
        .filter(
            db.query(OnpremClinicalNote)
            .filter(OnpremClinicalNote.encounter_id == OnpremEncounter.encounter_id)
            .exists()
        )
        .order_by(OnpremEncounter.visit_datetime.desc())
        .first()
    )
    if not encounter:
        raise HTTPException(status_code=404, detail="진료 기록이 없습니다.")

    notes = (
        db.query(OnpremClinicalNote)
        .filter(OnpremClinicalNote.encounter_id == encounter.encounter_id)
        .order_by(OnpremClinicalNote.created_at.desc())
        .all()
    )

    diagnoses = (
        db.query(OnpremDiagnosis)
        .filter(OnpremDiagnosis.encounter_id == encounter.encounter_id)
        .all()
    )

    response = {
        "encounter_id":    str(encounter.encounter_id),
        "encounter_type":  encounter.encounter_type,
        "department_code": encounter.department_code,
        "visit_datetime":  encounter.visit_datetime.isoformat() if encounter.visit_datetime else None,
        "chief_complaint": encounter.chief_complaint,
        "status_code":     encounter.status_code,
        "clinical_notes": [
            _decode_note(n) for n in notes
        ],
        "diagnoses": [
            {
                "diagnosis_code": d.diagnosis_code,
                "diagnosis_text": d.diagnosis_text,
                "is_primary":     d.is_primary,
            }
            for d in diagnoses
        ],
    }
    _record_audit(db, current_user["sub"], "VIEW_LATEST_ENCOUNTER", "200", request, pid)
    return response


# ── SFR-019 진료 기록 작성 ────────────────────────────────────────

class SoapNoteCreate(BaseModel):
    note_type: str
    note_text: str


class DoctorDiagnosisCreate(BaseModel):
    diagnosis_code: str
    diagnosis_text: str
    is_primary:     bool = False


class DoctorEncounterCreate(BaseModel):
    patient_id:      str
    department_code: str
    encounter_type:  str = "outpatient_return"
    chief_complaint: Optional[str] = None


class DoctorEncounterStatusUpdate(BaseModel):
    status_code: str


class DoctorAllergyCreate(BaseModel):
    allergy_name:  str
    allergy_code:  Optional[str] = None
    severity_code: str = "경증"
    is_active:     bool = True


class DoctorSurgeryCreate(BaseModel):
    surgery_name: str
    surgery_code: Optional[str] = None
    surgery_date: Optional[str] = None
    note:         Optional[str] = None


@router.post("/encounters", status_code=201)
def doctor_create_encounter(
    body:         DoctorEncounterCreate,
    request:      Request,
    current_user: dict      = Depends(_require_doctor),
    db:           DbSession = Depends(get_db),
):
    """진료 encounter 생성"""
    doctor_id = current_user.get("did")
    if not doctor_id:
        raise HTTPException(status_code=400, detail="의사 정보가 연결되지 않은 계정입니다.")

    try:
        pid = uuid.UUID(body.patient_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="유효하지 않은 patient_id 형식입니다.")

    patient = db.query(OnpremPatient).filter(OnpremPatient.patient_id == pid).first()
    if not patient:
        raise HTTPException(status_code=404, detail="환자를 찾을 수 없습니다.")

    now = datetime.now()
    encounter = OnpremEncounter(
        encounter_id    = uuid.uuid4(),
        patient_id      = pid,
        doctor_id       = uuid.UUID(str(doctor_id)),
        department_code = body.department_code,
        encounter_type  = body.encounter_type,
        chief_complaint = body.chief_complaint,
        visit_datetime  = now,
        status_code     = "OPEN",
        created_at      = now,
    )
    db.add(encounter)
    response = {
        "encounter_id":    str(encounter.encounter_id),
        "patient_id":      str(encounter.patient_id),
        "department_code": encounter.department_code,
        "visit_datetime":  encounter.visit_datetime.isoformat(),
        "status_code":     encounter.status_code,
    }
    _record_audit(db, current_user["sub"], "INSERT", "201", request, pid, target_table="encounters")
    db.commit()
    return response


@router.post("/encounters/{encounter_id}/notes", status_code=201)
def doctor_create_note(
    encounter_id: str,
    body:         SoapNoteCreate,
    request:      Request,
    current_user: dict      = Depends(_require_doctor),
    db:           DbSession = Depends(get_db),
):
    """진료 노트 작성 — 1등급 데이터"""
    try:
        eid = uuid.UUID(encounter_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="유효하지 않은 encounter_id 형식입니다.")

    encounter = db.query(OnpremEncounter).filter(OnpremEncounter.encounter_id == eid).first()
    if not encounter:
        raise HTTPException(status_code=404, detail="진료 기록을 찾을 수 없습니다.")

    # SOAP 타입(S/O/A/P)은 DB에 PROGRESS로 저장하고 접두어로 구분
    _SOAP_TYPES = {'S', 'O', 'A', 'P'}
    if body.note_type in _SOAP_TYPES:
        db_note_type = 'PROGRESS'
        db_note_text = f'[{body.note_type}] {body.note_text}'
    else:
        db_note_type = body.note_type
        db_note_text = body.note_text

    note = OnpremClinicalNote(
        note_id      = uuid.uuid4(),
        encounter_id = eid,
        patient_id   = encounter.patient_id,
        author_type  = "DOCTOR",
        note_type    = db_note_type,
        note_text    = db_note_text,
        created_at   = datetime.now(),
    )
    db.add(note)
    note_id = str(note.note_id)
    patient_id = encounter.patient_id
    db.commit()
    _record_audit(db, current_user["sub"], "CREATE_CLINICAL_NOTE", "201", request, patient_id)
    return {"note_id": note_id, "note_type": body.note_type}


@router.post("/encounters/{encounter_id}/diagnoses", status_code=201)
def doctor_create_diagnosis(
    encounter_id: str,
    body:         DoctorDiagnosisCreate,
    request:      Request,
    current_user: dict      = Depends(_require_doctor),
    db:           DbSession = Depends(get_db),
):
    """진단 기록 작성"""
    try:
        eid = uuid.UUID(encounter_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="유효하지 않은 encounter_id 형식입니다.")

    encounter = db.query(OnpremEncounter).filter(OnpremEncounter.encounter_id == eid).first()
    if not encounter:
        raise HTTPException(status_code=404, detail="진료 기록을 찾을 수 없습니다.")

    diagnosis = OnpremDiagnosis(
        diagnosis_id   = uuid.uuid4(),
        encounter_id   = eid,
        patient_id     = encounter.patient_id,
        diagnosis_code = body.diagnosis_code,
        diagnosis_text = body.diagnosis_text,
        is_primary     = body.is_primary,
        diagnosed_at   = datetime.now(),
    )
    db.add(diagnosis)
    response = {"diagnosis_id": str(diagnosis.diagnosis_id)}
    patient_id = encounter.patient_id
    _record_audit(db, current_user["sub"], "CREATE_DIAGNOSIS", "201", request, patient_id)
    db.commit()
    return response


@router.patch("/encounters/{encounter_id}")
def doctor_update_encounter(
    encounter_id: str,
    body:         DoctorEncounterStatusUpdate,
    request:      Request,
    current_user: dict      = Depends(_require_doctor),
    db:           DbSession = Depends(get_db),
):
    """진료 상태 업데이트"""
    try:
        eid = uuid.UUID(encounter_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="유효하지 않은 encounter_id 형식입니다.")

    encounter = db.query(OnpremEncounter).filter(OnpremEncounter.encounter_id == eid).first()
    if not encounter:
        raise HTTPException(status_code=404, detail="진료 기록을 찾을 수 없습니다.")

    encounter.status_code = body.status_code

    # 진료 완료(CLOSED) 시 오늘 예약도 completed 로 자동 전환
    if body.status_code == "CLOSED":
        patient = db.query(OnpremPatient).filter(
            OnpremPatient.patient_id == encounter.patient_id
        ).first()
        if patient and patient.patient_id_hash:
            completed_status = db.query(AppointmentStatus).filter(
                AppointmentStatus.status_code == "completed"
            ).first()
            if completed_status:
                from datetime import date
                appt = (
                    db.query(Appointment)
                    .filter(
                        Appointment.patient_id_hash == patient.patient_id_hash,
                        Appointment.doctor_id       == encounter.doctor_id,
                        Appointment.appointment_date == date.today(),
                    )
                    .filter(
                        db.query(AppointmentStatus)
                        .filter(
                            AppointmentStatus.status_id  == Appointment.status_id,
                            AppointmentStatus.is_terminal == False,
                        )
                        .exists()
                    )
                    .first()
                )
                if appt:
                    db.add(AppointmentHistory(
                        appointment_id = appt.appointment_id,
                        changed_by     = uuid.UUID(current_user["sub"]),
                        prev_status_id = appt.status_id,
                        new_status_id  = completed_status.status_id,
                    ))
                    appt.status_id  = completed_status.status_id
                    appt.updated_at = datetime.now(timezone.utc)

    patient_id   = encounter.patient_id
    response = {
        "encounter_id": str(encounter.encounter_id),
        "status_code":  encounter.status_code,
    }
    db.commit()
    _record_audit(db, current_user["sub"], "UPDATE_ENCOUNTER", "200", request, patient_id)
    return response


# ── Break-glass 긴급 접근 ────────────────────────────────────────

@router.post("/patients/{patient_id}/allergies", status_code=201)
def doctor_add_allergy(
    patient_id:   str,
    body:         DoctorAllergyCreate,
    request:      Request,
    current_user: dict      = Depends(_require_doctor),
    db:           DbSession = Depends(get_db),
):
    """알레르기 추가"""
    try:
        pid = uuid.UUID(patient_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="유효하지 않은 patient_id 형식입니다.")

    allergy = OnpremAllergy(
        allergy_id    = uuid.uuid4(),
        patient_id    = pid,
        allergy_code  = body.allergy_code or None,
        allergy_name  = body.allergy_name,
        severity_code = body.severity_code,
        is_active     = body.is_active,
        recorded_at   = datetime.now(),
        updated_at    = datetime.now(),
    )
    db.add(allergy)
    _record_audit(db, current_user["sub"], "INSERT", "201", request, pid, target_table="allergies")
    db.commit()
    return {"allergy_id": str(allergy.allergy_id)}


@router.post("/patients/{patient_id}/surgeries", status_code=201)
def doctor_add_surgery(
    patient_id:   str,
    body:         DoctorSurgeryCreate,
    request:      Request,
    current_user: dict      = Depends(_require_doctor),
    db:           DbSession = Depends(get_db),
):
    """수술 이력 추가"""
    from datetime import date as date_type
    try:
        pid = uuid.UUID(patient_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="유효하지 않은 patient_id 형식입니다.")

    surgery_date = None
    if body.surgery_date:
        try:
            surgery_date = date_type.fromisoformat(body.surgery_date)
        except ValueError:
            raise HTTPException(status_code=422, detail="수술 날짜 형식이 올바르지 않습니다 (YYYY-MM-DD).")

    surgery = OnpremSurgery(
        surgery_history_id = uuid.uuid4(),
        patient_id         = pid,
        surgery_code       = body.surgery_code or None,
        surgery_name       = body.surgery_name,
        surgery_date       = surgery_date,
        note               = body.note or None,
        updated_at         = datetime.now(),
    )
    db.add(surgery)
    _record_audit(db, current_user["sub"], "INSERT", "201", request, pid, target_table="surgery_histories")
    db.commit()
    return {"surgery_history_id": str(surgery.surgery_history_id)}


# @router.post("/patients/{patient_id}/break-glass")
# def doctor_break_glass(
#     patient_id:   str,
#     request:      Request,
#     current_user: dict      = Depends(_require_doctor),
#     db:           DbSession = Depends(get_db),
# ):
#     """비담당 환자 긴급 EMR 접근 — 감사 로그 필수 기록 (ISMS-P 2.9.1)"""
#     try:
#         pid = uuid.UUID(patient_id)
#     except ValueError:
#         raise HTTPException(status_code=422, detail="유효하지 않은 patient_id 형식입니다.")
#
#     patient = db.query(OnpremPatient).filter(OnpremPatient.patient_id == pid).first()
#     if not patient:
#         raise HTTPException(status_code=404, detail="환자를 찾을 수 없습니다.")
#
#     from core.security import record_audit
#     record_audit(
#         db,
#         action_type  = "BREAK_GLASS_ACCESS",
#         result_code  = "200",
#         user_id      = current_user["sub"],
#         patient_id   = pid,
#         target_table = "patients",
#         source_ip    = request.client.host if request.client else None,
#     )
#     db.commit()
#
#     logger.warning(
#         "BREAK-GLASS: 의사 %s가 비담당 환자 %s EMR에 긴급 접근 (IP: %s)",
#         current_user["sub"], patient_id,
#         request.client.host if request.client else "unknown"
#     )
#
#     return {"message": "긴급 접근이 기록되었습니다.", "patient_id": patient_id}

