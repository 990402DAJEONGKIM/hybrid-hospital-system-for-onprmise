"""
로깅 설정.

- 앱 로그: stdout (Docker 표준)
- 감사 로그: /var/log/onprem-emr/audit.log (파일 영구 보관)
- CloudWatch 핸들러: CLOUDWATCH_LOG_GROUP 설정 시 활성화
"""
import logging
import logging.config
import os

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
AUDIT_LOG_PATH = os.getenv("AUDIT_LOG_PATH", "/var/log/onprem-emr/audit.log")

os.makedirs(os.path.dirname(AUDIT_LOG_PATH), exist_ok=True)

LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "default": {
            "format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        },
        "audit": {
            "format": "%(message)s",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "default",
            "stream": "ext://sys.stdout",
        },
        "audit_file": {
            "class": "logging.handlers.TimedRotatingFileHandler",
            "formatter": "audit",
            "filename": AUDIT_LOG_PATH,
            "when": "midnight",
            "backupCount": 90,      # 90일 보관 (ISMS-P 최소 요건)
            "encoding": "utf-8",
        },
    },
    "loggers": {
        "audit": {
            "handlers": ["audit_file", "console"],
            "level": "INFO",
            "propagate": False,
        },
        "wazuh.audit": {
            "handlers": ["audit_file", "console"],
            "level": "INFO",
            "propagate": False,
        },
    },
    "root": {
        "handlers": ["console"],
        "level": LOG_LEVEL,
    },

}
def setup_logging():
    logging.config.dictConfig(LOGGING_CONFIG)
