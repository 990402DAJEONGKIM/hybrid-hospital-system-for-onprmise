import os
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean, Column, Date, DateTime, ForeignKey,
    Integer, SmallInteger, String, Text, Time, Uuid,
)
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.orm import relationship

from core.database import Base

# DB_MODE: cloud(AWS RDS) vs onprem — by 김다정, 2026-06-06
# cloud : users.patient_id_hash varchar, audit_logs.patient_id_hash, appointments.patient_user_id
# onprem: users.patient_id UUID FK,      audit_logs.patient_id UUID,  appointments에 patient_user_id 없음
DB_MODE = os.getenv("DB_MODE", "cloud")


# ============================================================
# 역할 / 권한 (RBAC) — ISMS-P 2.5.4
# ============================================================

class Role(Base):
    __tablename__ = "roles"

    role_id     = Column(Integer,      primary_key=True, autoincrement=True)
    role_code   = Column(String(30),   nullable=False, unique=True)
    role_name   = Column(String(100),  nullable=False)
    description = Column(Text)
    is_active   = Column(Boolean,      nullable=False, default=True)
    created_at  = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    users            = relationship("User",           back_populates="role_ref")
    role_permissions = relationship("RolePermission", back_populates="role")
    role_menus       = relationship("RoleMenu",       back_populates="role")


class Permission(Base):
    __tablename__ = "permissions"

    permission_id   = Column(Integer,     primary_key=True, autoincrement=True)
    permission_code = Column(String(50),  nullable=False, unique=True)
    permission_name = Column(String(100), nullable=False)
    category        = Column(String(30))
    description     = Column(Text)

    role_permissions = relationship("RolePermission", back_populates="permission")


class RolePermission(Base):
    __tablename__ = "role_permissions"

    role_id       = Column(Integer, ForeignKey("roles.role_id",       ondelete="CASCADE"), primary_key=True)
    permission_id = Column(Integer, ForeignKey("permissions.permission_id", ondelete="CASCADE"), primary_key=True)

    role       = relationship("Role",       back_populates="role_permissions")
    permission = relationship("Permission", back_populates="role_permissions")


class Menu(Base):
    __tablename__ = "menus"

    menu_id    = Column(Integer,     primary_key=True, autoincrement=True)
    menu_code  = Column(String(50),  nullable=False, unique=True)
    menu_name  = Column(String(100), nullable=False)
    menu_url   = Column(String(200))
    parent_id  = Column(Integer,     ForeignKey("menus.menu_id"))
    sort_order = Column(Integer,     nullable=False, default=0)
    is_active  = Column(Boolean,     nullable=False, default=True)

    role_menus = relationship("RoleMenu", back_populates="menu")


class RoleMenu(Base):
    __tablename__ = "role_menus"

    role_id = Column(Integer, ForeignKey("roles.role_id", ondelete="CASCADE"), primary_key=True)
    menu_id = Column(Integer, ForeignKey("menus.menu_id", ondelete="CASCADE"), primary_key=True)

    role = relationship("Role", back_populates="role_menus")
    menu = relationship("Menu", back_populates="role_menus")


# ============================================================
# 인증 — ISMS-P 2.5.1 / 2.5.3 / 2.9.1
# ============================================================

class User(Base):
    __tablename__ = "users"

    user_id              = Column(Uuid,        primary_key=True, default=uuid.uuid4)
    email                = Column(String(255), nullable=True, unique=True)
    password_hash        = Column(String(255), nullable=False)
    role_id              = Column(Integer,     ForeignKey("roles.role_id"), nullable=False)
    # DB_MODE 분기: 클라우드는 patient_id_hash varchar, 온프레미스는 patient_id UUID FK — by 김다정, 2026-06-06
    patient_id_hash = Column(String(64), nullable=True) if DB_MODE == "cloud" else None
    patient_id      = Column(Uuid, ForeignKey("patients.patient_id"), nullable=True) if DB_MODE == "onprem" else None
    doctor_id            = Column(Uuid)
    is_active            = Column(Boolean,      nullable=False, default=True)
    failed_login_cnt     = Column(SmallInteger, nullable=False, default=0)
    locked_until         = Column(DateTime(timezone=True))
    last_login_at        = Column(DateTime(timezone=True))
    password_changed_at  = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    created_at           = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at           = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    member_number        = Column(String(20),  unique=True)
    must_change_password = Column(Boolean,     nullable=False, default=True)
    password_expires_at  = Column(DateTime(timezone=True))
    display_name         = Column(String(100))
    synced_at            = Column(DateTime(timezone=True))

    role_ref      = relationship("Role",         back_populates="users")
    sessions      = relationship("Session",      back_populates="user")
    login_history = relationship("LoginHistory", back_populates="user")
    mfa           = relationship("UserMfa",      back_populates="user", uselist=False)


class UserMfa(Base):
    __tablename__ = "user_mfa"

    mfa_id      = Column(Uuid,                   primary_key=True, default=uuid.uuid4)
    user_id     = Column(Uuid,                   ForeignKey("users.user_id", ondelete="CASCADE"), nullable=False)
    mfa_type    = Column(String(10),             nullable=False, default="totp")
    secret      = Column(String(64),             nullable=False)
    is_active   = Column(Boolean,                nullable=False, default=False)
    created_at  = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    verified_at = Column(DateTime(timezone=True))
    synced_at   = Column(DateTime(timezone=True))

    user = relationship("User", back_populates="mfa")


class Session(Base):
    __tablename__ = "sessions"

    session_id         = Column(Uuid,       primary_key=True, default=uuid.uuid4)
    user_id            = Column(Uuid,       ForeignKey("users.user_id", ondelete="CASCADE"), nullable=False)
    refresh_token_hash = Column(String(64), nullable=False, unique=True)
    user_agent         = Column(Text)
    ip_address         = Column(INET)
    expires_at         = Column(DateTime(timezone=True), nullable=False)
    last_used_at       = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    created_at         = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    is_revoked         = Column(Boolean, nullable=False, default=False)

    user = relationship("User", back_populates="sessions")


class PasswordPolicy(Base):
    __tablename__ = "password_policy"

    policy_id         = Column(Integer, primary_key=True, autoincrement=True)
    min_length        = Column(Integer, nullable=False, default=8)
    require_uppercase = Column(Boolean, nullable=False, default=True)
    require_lowercase = Column(Boolean, nullable=False, default=True)
    require_digit     = Column(Boolean, nullable=False, default=True)
    require_special   = Column(Boolean, nullable=False, default=True)
    expire_days       = Column(Integer, nullable=False, default=90)
    max_failed_logins = Column(Integer, nullable=False, default=5)
    lockout_minutes   = Column(Integer, nullable=False, default=30)
    updated_at        = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_by        = Column(Uuid, ForeignKey("users.user_id"))


class LoginHistory(Base):
    __tablename__ = "login_history"

    history_id = Column(Uuid,        primary_key=True, default=uuid.uuid4)
    user_id    = Column(Uuid,        ForeignKey("users.user_id", ondelete="SET NULL"), nullable=True)
    email      = Column(String(255))
    result     = Column(String(10),  nullable=False)  # 'success', 'fail', 'locked'
    ip_address = Column(INET)
    user_agent = Column(Text)
    event_at   = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    user = relationship("User", back_populates="login_history")


# ============================================================
# 예약 — SFR-001
# ============================================================

class AppointmentType(Base):
    __tablename__ = "appointment_types"

    type_id                 = Column(Integer,     primary_key=True, autoincrement=True)
    type_code               = Column(String(30),  nullable=False, unique=True)
    type_name               = Column(String(100), nullable=False)
    requires_previous_visit = Column(Boolean,     nullable=False, default=False)
    description             = Column(Text)
    is_active               = Column(Boolean,     nullable=False, default=True)
    sort_order              = Column(Integer,     nullable=False, default=0)

    appointments = relationship("Appointment", back_populates="appt_type")


class AppointmentStatus(Base):
    __tablename__ = "appointment_statuses"

    status_id   = Column(Integer,    primary_key=True, autoincrement=True)
    status_code = Column(String(20), nullable=False, unique=True)
    status_name = Column(String(50), nullable=False)
    is_terminal = Column(Boolean,    nullable=False, default=False)
    sort_order  = Column(Integer,    nullable=False, default=0)


class Patient(Base):
    __tablename__ = "patients"

    patient_id           = Column(Uuid,         primary_key=True, default=uuid.uuid4)
    patient_name         = Column(String(100),  nullable=False)
    national_id_encrypted = Column(Text,        nullable=False)
    birth_date           = Column(Date,         nullable=False)
    gender_code          = Column(String(1),    nullable=False)
    phone_number         = Column(String(20),   nullable=False)
    email                = Column(String(255))
    address              = Column(Text)
    created_at           = Column(DateTime,     nullable=False)
    updated_at           = Column(DateTime,     nullable=False)
    patient_id_hash      = Column(String(255),  nullable=False)
    member_number        = Column(String(20))
    internal_seq         = Column(String(20))


class Appointment(Base):
    __tablename__ = "appointments"

    appointment_id  = Column(Uuid, primary_key=True, default=uuid.uuid4)
    # cloud RDS 에는 patient_user_id (NOT NULL) 존재, 온프레미스에는 없음 — by 김다정, 2026-06-06
    patient_user_id = Column(Uuid, ForeignKey("users.user_id"), nullable=False) if DB_MODE == "cloud" else None
    patient_id_hash = Column(String(64), ForeignKey("sync_patients.patient_id_hash"))
    type_id               = Column(Integer,     ForeignKey("appointment_types.type_id"), nullable=False)
    status_id             = Column(Integer,     ForeignKey("appointment_statuses.status_id"), nullable=False)
    department_code       = Column(String(20),  ForeignKey("sync_departments.department_code"))
    doctor_id             = Column(Uuid,        ForeignKey("sync_doctors.doctor_id"))
    ward_id               = Column(Uuid,        ForeignKey("sync_wards.ward_id"))
    room_type_pref        = Column(String(20))  # 'shared', 'double', 'single'
    has_chronic_condition = Column(Boolean)     # 입원 예약 시 기저질환 유무
    appointment_date      = Column(Date,        nullable=False)
    appointment_time      = Column(Time,        nullable=False)
    confirmed_at          = Column(DateTime(timezone=True))
    confirmed_by          = Column(Uuid,        ForeignKey("users.user_id"))
    cancelled_at          = Column(DateTime(timezone=True))
    cancelled_by          = Column(Uuid,        ForeignKey("users.user_id"))
    cancel_reason         = Column(String(200))
    notes                 = Column(Text)
    created_at            = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at            = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    appt_type   = relationship("AppointmentType",    back_populates="appointments")
    appt_status = relationship("AppointmentStatus")
    history     = relationship("AppointmentHistory", back_populates="appointment")


class AppointmentHistory(Base):
    __tablename__ = "appointment_history"

    history_id     = Column(Uuid,        primary_key=True, default=uuid.uuid4)
    appointment_id = Column(Uuid,        ForeignKey("appointments.appointment_id", ondelete="CASCADE"), nullable=False)
    changed_by     = Column(Uuid,        ForeignKey("users.user_id"))
    prev_status_id = Column(Integer,     ForeignKey("appointment_statuses.status_id"))
    new_status_id  = Column(Integer,     ForeignKey("appointment_statuses.status_id"))
    prev_date      = Column(Date)
    new_date       = Column(Date)
    prev_time      = Column(Time)
    new_time       = Column(Time)
    change_reason  = Column(String(200))
    changed_at     = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    appointment = relationship("Appointment", back_populates="history")


# ============================================================
# 병동 (온프레미스 sync) — SFR-001 입원
# ============================================================

class SyncWard(Base):
    __tablename__ = "sync_wards"

    ward_id         = Column(Uuid,        primary_key=True)
    ward_name       = Column(String(100))
    room_type       = Column(String(20))   # 'shared', 'double', 'single'
    total_beds      = Column(SmallInteger)
    available_beds  = Column(SmallInteger)
    department_code = Column(String(20))
    synced_at       = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at      = Column(DateTime(timezone=True))


# ============================================================
# 알림 — SFR-001 (AWS SES)
# ============================================================

class NotificationType(Base):
    __tablename__ = "notification_types"

    notification_type_id = Column(Integer,     primary_key=True, autoincrement=True)
    type_code            = Column(String(30),  nullable=False, unique=True)
    type_name            = Column(String(100), nullable=False)
    email_subject_tmpl   = Column(Text)
    email_body_tmpl      = Column(Text)
    is_active            = Column(Boolean,     nullable=False, default=True)

    notifications = relationship("Notification", back_populates="notif_type")


class Notification(Base):
    __tablename__ = "notifications"

    notification_id      = Column(Uuid,        primary_key=True, default=uuid.uuid4)
    user_id              = Column(Uuid,        ForeignKey("users.user_id"), nullable=False)
    notification_type_id = Column(Integer,     ForeignKey("notification_types.notification_type_id"))
    appointment_id       = Column(Uuid,        ForeignKey("appointments.appointment_id"))
    channel              = Column(String(20),  nullable=False, default="email")
    status               = Column(String(20),  nullable=False, default="pending")
    sent_at              = Column(DateTime(timezone=True))
    error_message        = Column(Text)
    created_at           = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    notif_type = relationship("NotificationType", back_populates="notifications")


# ============================================================
# 온프레미스 → AWS 복제 테이블 (pglogical, 읽기 전용)
# ============================================================

class SyncPatient(Base):
    __tablename__ = "sync_patients"

    patient_id_hash = Column(String(64), primary_key=True)
    birth_year      = Column(SmallInteger)
    gender_code     = Column(String(1))
    phone_hash      = Column(String(64))
    created_at      = Column(DateTime(timezone=True))
    synced_at       = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class SyncDepartment(Base):
    __tablename__ = "sync_departments"

    department_code = Column(String(20),  primary_key=True)
    department_name = Column(String(100))
    is_active       = Column(Boolean)
    updated_at      = Column(DateTime(timezone=True))
    synced_at       = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class SyncDoctor(Base):
    __tablename__ = "sync_doctors"

    doctor_id       = Column(Uuid,       primary_key=True)
    doctor_name     = Column(String(100))
    department_code = Column(String(20), ForeignKey("sync_departments.department_code"))
    is_active       = Column(Boolean)
    updated_at      = Column(DateTime(timezone=True))
    synced_at       = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class SyncEncounter(Base):
    __tablename__ = "sync_encounters"

    encounter_id    = Column(String(36), primary_key=True)
    patient_id_hash = Column(String(64))
    encounter_type  = Column(String(30))
    department_code = Column(String(20), ForeignKey("sync_departments.department_code"))
    doctor_id       = Column(Uuid,       ForeignKey("sync_doctors.doctor_id"))
    visit_date      = Column(Date)
    status_code     = Column(String(20))
    created_at      = Column(DateTime(timezone=True))
    synced_at       = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class SyncDiagnosis(Base):
    __tablename__ = "sync_diagnoses"

    diagnosis_id    = Column(String(36), primary_key=True)
    encounter_id    = Column(String(36), ForeignKey("sync_encounters.encounter_id"))
    patient_id_hash = Column(String(64))
    diagnosis_code  = Column(String(20))
    is_primary      = Column(Boolean)
    diagnosed_at    = Column(DateTime(timezone=True))
    synced_at       = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class SyncAllergy(Base):
    __tablename__ = "sync_allergies"

    allergy_id      = Column(String(36), primary_key=True)
    patient_id_hash = Column(String(64))
    allergy_name    = Column(String)
    severity_code   = Column(String(10))
    synced_at       = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class SyncSurgery(Base):
    __tablename__ = "sync_surgery_histories"

    surgery_history_id = Column(String(36), primary_key=True)
    patient_id_hash    = Column(String(64))
    surgery_name       = Column(String)
    surgery_date       = Column(Date)
    synced_at          = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


# ============================================================
# 온프레미스 원본 테이블 — DB_MODE=onprem 전용
# ============================================================

class OnpremDepartment(Base):
    __tablename__ = "departments"

    department_code = Column(String(20),  primary_key=True)
    department_name = Column(String(100))
    is_active       = Column(Boolean)
    updated_at      = Column(DateTime(timezone=False))


class OnpremDoctor(Base):
    __tablename__ = "doctors"

    doctor_id       = Column(Uuid,       primary_key=True)
    doctor_name     = Column(String(100))
    department_code = Column(String(20))
    is_active       = Column(Boolean)
    updated_at      = Column(DateTime(timezone=False))


class OnpremEncounter(Base):
    __tablename__ = "encounters"

    encounter_id     = Column(Uuid,        primary_key=True)
    patient_id       = Column(Uuid)
    encounter_type   = Column(String(30))
    department_code  = Column(String(20))
    doctor_id        = Column(Uuid)
    visit_datetime   = Column(DateTime(timezone=False))
    chief_complaint  = Column(Text)
    status_code      = Column(String(20))
    created_at       = Column(DateTime(timezone=False))
    updated_at       = Column(DateTime(timezone=False))


class OnpremDiagnosis(Base):
    __tablename__ = "diagnoses"

    diagnosis_id    = Column(Uuid,        primary_key=True)
    encounter_id    = Column(Uuid)
    patient_id      = Column(Uuid)
    diagnosis_code  = Column(String(20))
    diagnosis_text  = Column(Text)
    is_primary      = Column(Boolean)
    diagnosed_at    = Column(DateTime(timezone=False))
    updated_at      = Column(DateTime(timezone=False))


class OnpremAllergy(Base):
    __tablename__ = "allergies"

    allergy_id    = Column(Uuid,        primary_key=True)
    patient_id    = Column(Uuid)
    allergy_code  = Column(String(50))
    allergy_name  = Column(Text)
    severity_code = Column(String(20))
    is_active     = Column(Boolean)
    recorded_at   = Column(DateTime(timezone=False))
    updated_at    = Column(DateTime(timezone=False))


class OnpremSurgery(Base):
    __tablename__ = "surgery_histories"

    surgery_history_id = Column(Uuid, primary_key=True)
    patient_id         = Column(Uuid)
    surgery_code       = Column(String(50))
    surgery_name       = Column(Text)
    surgery_date       = Column(Date)
    note               = Column(Text)
    updated_at         = Column(DateTime(timezone=False))


class OnpremClinicalNote(Base):
    __tablename__ = "clinical_notes"

    note_id      = Column(Uuid,        primary_key=True)
    encounter_id = Column(Uuid)
    patient_id   = Column(Uuid)
    author_type  = Column(String(20))
    note_type    = Column(String(30))
    note_text    = Column(Text)
    created_at   = Column(DateTime(timezone=False))


# ============================================================
# 감사 로그 — ISMS-P 2.9.1
# ============================================================

class AuditLog(Base):
    __tablename__ = "audit_logs"

    audit_log_id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id      = Column(Uuid, ForeignKey("users.user_id", ondelete="SET NULL"), nullable=True)
    # DB_MODE 분기: 클라우드는 patient_id_hash varchar, 온프레미스는 patient_id UUID — by 김다정, 2026-06-06
    patient_id_hash = Column(String(64), nullable=True) if DB_MODE == "cloud" else None
    patient_id      = Column(Uuid,       nullable=True) if DB_MODE == "onprem"  else None
    action_type     = Column(String(50), nullable=False)
    target_table = Column(String(50))
    target_id    = Column(Uuid)
    source_ip    = Column(INET)
    result_code  = Column(String(20))
    event_at     = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))



# ============================================================
# 입퇴원 관리 — SFR-INP
# ============================================================

class Bed(Base):
    __tablename__ = "beds"

    bed_id      = Column(Uuid, primary_key=True, default=uuid.uuid4)
    ward_id     = Column(Uuid, ForeignKey("sync_wards.ward_id"))
    room_number = Column(String(20))
    status      = Column(String(20))  # AVAILABLE / OCCUPIED / MAINTENANCE
    created_at  = Column(DateTime(timezone=True))
    updated_at  = Column(DateTime(timezone=True))


class Admission(Base):
    __tablename__ = "admissions"

    admission_id            = Column(Uuid, primary_key=True, default=uuid.uuid4)
    appointment_id          = Column(Uuid, ForeignKey("appointments.appointment_id"))
    patient_id_hash         = Column(String(64))
    ward_id                 = Column(Uuid, ForeignKey("sync_wards.ward_id"))
    bed_id                  = Column(Uuid, ForeignKey("beds.bed_id"))
    room_type               = Column(String(20))
    admitted_by             = Column(Uuid, ForeignKey("users.user_id"))
    discharge_ordered_by    = Column(Uuid, ForeignKey("users.user_id"))
    admitted_at             = Column(DateTime(timezone=True))
    expected_discharge_date = Column(Date)
    discharged_at           = Column(DateTime(timezone=True))
    status                  = Column(String(20))  # ADMITTED / DISCHARGE_ORDERED / DISCHARGED
    notes                   = Column(Text)
    created_at              = Column(DateTime(timezone=True))
    updated_at              = Column(DateTime(timezone=True))


class PatientEmrSummary(Base):
    """AI 요약 테이블 — 1등급 개인정보 (RDS/GCP 전송 금지)"""
    __tablename__ = "patient_emr_summary"
    patient_id   = Column(Uuid,    primary_key=True)
    summary_text = Column(Text,    nullable=False)
    generated_at = Column(DateTime(timezone=True))
    source_hash  = Column(String(64))
