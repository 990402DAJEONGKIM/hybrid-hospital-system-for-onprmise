import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

SES_FROM_EMAIL = os.getenv("SES_FROM_EMAIL", "")
ADMIN_EMAIL    = os.getenv("ADMIN_EMAIL", "")
AWS_REGION     = os.getenv("AWS_REGION", "ap-northeast-2")

_APPT_SUBJECT = {
    "pending":   "[MZ Clinic] 예약 접수 확인",
    "confirmed": "[MZ Clinic] 예약이 확정되었습니다",
    "updated":   "[MZ Clinic] 예약 일정이 변경되었습니다",
    "cancelled": "[MZ Clinic] 예약이 취소되었습니다",
}

_APPT_BODY = {
    "pending": (
        "안녕하세요, MZ Clinic입니다.\n\n"
        "예약이 정상적으로 접수되었습니다.\n"
        "원무과 확인 후 확정 알림을 별도로 보내드리겠습니다.\n\n"
        "  유형   : {type}\n"
        "  진료과 : {dept}\n"
        "  예약일 : {date}\n"
        "  시간   : {time}\n\n"
        "문의: MZ Clinic 원무과\n"
        "예약 취소 또는 변경은 환자 포털에서 가능합니다."
    ),
    "confirmed": (
        "안녕하세요, MZ Clinic입니다.\n\n"
        "예약이 확정되었습니다.\n\n"
        "  유형   : {type}\n"
        "  진료과 : {dept}\n"
        "  예약일 : {date}\n"
        "  시간   : {time}\n\n"
        "방문 예정일에 원무과에 내원해 주세요.\n"
        "문의: MZ Clinic 원무과"
    ),
    "updated": (
        "안녕하세요, MZ Clinic입니다.\n\n"
        "예약 일정이 변경되었습니다.\n\n"
        "  유형     : {type}\n"
        "  진료과   : {dept}\n"
        "  변경 전  : {prev_date} {prev_time}\n"
        "  변경 후  : {date} {time}\n\n"
        "문의: MZ Clinic 원무과\n"
        "예약 취소 또는 변경은 환자 포털에서 가능합니다."
    ),
    "cancelled": (
        "안녕하세요, MZ Clinic입니다.\n\n"
        "예약이 취소되었습니다.\n\n"
        "  유형   : {type}\n"
        "  진료과 : {dept}\n"
        "  예약일 : {date}\n\n"
        "새로운 예약은 환자 포털에서 진행해 주세요.\n"
        "문의: MZ Clinic 원무과"
    ),
}


def _mask_email(email: str) -> str:
    """로그용 이메일 마스킹 — 수신자 풀 이메일 로그 노출 방지 (TC-13 Step 6)."""
    try:
        local, domain = email.split("@", 1)
        return f"{local[:2]}***@{domain}"
    except (ValueError, AttributeError):
        return "***"


def _ses_send(to_email: str, subject: str, body: str) -> bool:
    """공통 SES 발송 헬퍼. 성공 여부를 bool로 반환."""
    if not SES_FROM_EMAIL:
        logger.warning("SES_FROM_EMAIL 미설정 — 알림 생략: %s", _mask_email(to_email))
        return False
    try:
        import boto3
        from botocore.config import Config
        client = boto3.client(
            "ses",
            region_name=AWS_REGION,
            # 발송 실패 시 무한 재시도 방지 — 최대 3회 (TC-13 Step 5)
            config=Config(retries={"max_attempts": 3, "mode": "standard"}),
        )
        client.send_email(
            Source      = SES_FROM_EMAIL,
            Destination = {"ToAddresses": [to_email]},
            Message     = {
                "Subject": {"Data": subject,  "Charset": "UTF-8"},
                "Body":    {"Text": {"Data": body, "Charset": "UTF-8"}},
            },
        )
        logger.info("SES 발송 완료: %s → %s", subject[:30], _mask_email(to_email))
        return True
    except ImportError:
        logger.warning("boto3 미설치 — SES 알림 생략 (%s)", _mask_email(to_email))
        return False
    except Exception as exc:
        logger.error("SES 발송 실패 (%s): %s", _mask_email(to_email), exc)
        return False


def send_lockout_alert(
    target_email: str,
    ip_address:   Optional[str],
    locked_until: str,
) -> None:
    """계정 잠금 시 관리자 이메일 알림."""
    if not SES_FROM_EMAIL or not ADMIN_EMAIL:
        logger.warning(
            "SES 환경변수(SES_FROM_EMAIL, ADMIN_EMAIL) 미설정 — 계정 잠금 알림 생략: %s",
            target_email,
        )
        return

    subject = f"[보안 알림] 계정 잠금 발생: {target_email}"
    body = (
        f"계정 잠금이 발생했습니다.\n\n"
        f"  이메일   : {target_email}\n"
        f"  접속 IP  : {ip_address or '알 수 없음'}\n"
        f"  잠금 해제: {locked_until} (UTC)\n\n"
        f"관리자 화면에서 계정 상태를 확인하세요."
    )
    _ses_send(ADMIN_EMAIL, subject, body)


def send_appointment_notification(
    to_email:  str,
    status:    str,
    appt_date: str,
    appt_time: Optional[str] = None,
    dept_code: Optional[str] = None,
    type_name: Optional[str] = None,
    prev_date: Optional[str] = None,
    prev_time: Optional[str] = None,
) -> bool:
    """예약 상태 변경 시 환자에게 이메일 알림.

    status: 'pending' | 'confirmed' | 'updated' | 'cancelled'
    updated는 변경 전·후 일시를 포함한다 (TC-13 Step 3).
    SES_FROM_EMAIL 미설정 또는 boto3 미설치 시 False를 반환하며
    메인 트랜잭션에 영향을 주지 않는다.
    """
    subject   = _APPT_SUBJECT.get(status, "[MZ Clinic] 예약 알림")
    body_tmpl = _APPT_BODY.get(status, "예약 상태가 변경되었습니다.")
    body = body_tmpl.format(
        type      = type_name or "-",
        dept      = dept_code or "-",
        date      = appt_date or "-",
        time      = appt_time or "-",
        prev_date = prev_date or "-",
        prev_time = prev_time or "-",
    )
    return _ses_send(to_email, subject, body)

