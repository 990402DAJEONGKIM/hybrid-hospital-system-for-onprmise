"""Vault 시크릿 로더 — 앱 기동 시 HashiCorp Vault에서 시크릿을 읽어 os.environ에 주입.

경로: secret/data/hospital/deident
  ├─ HASH_SALT
  ├─ API_KEY
  ├─ JWT_SECRET
  ├─ JWT_SECRET_PREVIOUS
  └─ RDS_SECRET_ID

지원 인증 방법:
  1. Token   (VAULT_TOKEN 설정 시) — 로컬 개발 / CI
  2. 미설정  (VAULT_ADDR 없을 때)  — 기존 환경변수 직접 사용 (하위 호환)

실패 시 RuntimeError → 앱 기동 중단 (시크릿 없이 기동하는 것보다 안전).
"""

import logging
import os

logger = logging.getLogger(__name__)

VAULT_ADDR  = os.getenv("VAULT_ADDR",  "")
# VAULT_ROLE  = os.getenv("VAULT_ROLE",  "")        # AWS IAM auth 미사용 — 온프레미스 DB는 온프레미스 내부에서 연결
VAULT_TOKEN = os.getenv("VAULT_TOKEN", "")          # Token auth: 로컬·CI·온프레미스 폴백
if not VAULT_TOKEN:
    token_file = os.getenv("VAULT_TOKEN_FILE", "")
    if token_file and os.path.exists(token_file):
        with open(token_file) as f:
            VAULT_TOKEN = f.read().strip()
VAULT_PATH  = os.getenv("VAULT_PATH",  "hospital/deident")
VAULT_MOUNT = os.getenv("VAULT_MOUNT", "secret")
# AWS_REGION  = os.getenv("AWS_REGION",  "ap-south-2")  # AWS IAM auth 미사용

# secret/data/hospital/deident 경로에서 읽어올 키 목록
_VAULT_KEYS = {
    "JWT_SECRET",
    "JWT_SECRET_PREVIOUS",
    "API_KEY",
    "HASH_SALT",
    "RDS_SECRET_ID",
    "MFA_ENC_KEY",
}


def load_vault_secrets() -> None:
    """Vault에서 시크릿을 읽어 os.environ에 주입.

    VAULT_ADDR 미설정 시 즉시 반환 (로컬 개발 환경 호환).
    인증 실패·경로 오류 시 RuntimeError 발생 → uvicorn 기동 중단.
    """
    if not VAULT_ADDR:
        logger.info("VAULT_ADDR 미설정 — 환경변수 직접 사용 (로컬 모드)")
        return

    try:
        import hvac
    except ImportError:
        raise RuntimeError(
            "hvac 패키지가 필요합니다. requirements.txt에 hvac 추가 후 재설치하세요."
        )

    client = hvac.Client(url=VAULT_ADDR)

    # 함수 호출 시점에 token 파일 재확인 (모듈 로드 시점과 다를 수 있음)
    vault_token = VAULT_TOKEN
    if not vault_token:
        token_file = os.getenv("VAULT_TOKEN_FILE", "")
        if token_file and os.path.exists(token_file):
            with open(token_file) as f:
                vault_token = f.read().strip()

    if vault_token:
        logger.info("Vault Token 인증 사용")
        client.token = vault_token


    else:
        raise RuntimeError(
            "Vault 인증 정보 없음. VAULT_TOKEN을 설정하세요."
        )

    if not client.is_authenticated():
        raise RuntimeError("Vault 인증 실패 — 토큰이 유효하지 않습니다.")

    # ── 시크릿 읽기 ──────────────────────────────────────────
    try:
        response = client.secrets.kv.v2.read_secret_version(
            path=VAULT_PATH,
            mount_point=VAULT_MOUNT,
            raise_on_deleted_version=True,
        )
    except Exception as exc:
        raise RuntimeError(
            f"Vault 시크릿 읽기 실패 (mount={VAULT_MOUNT}, path={VAULT_PATH}): {exc}"
        ) from exc

    data: dict = response.get("data", {}).get("data", {})
    if not data:
        raise RuntimeError(
            f"Vault 응답이 비어 있습니다 (mount={VAULT_MOUNT}, path={VAULT_PATH})"
        )

    # ── os.environ 주입 ──────────────────────────────────────
    injected: list[str] = []
    for key in _VAULT_KEYS:
        value = data.get(key)
        if value:
            os.environ[key] = str(value)
            injected.append(key)
        else:
            logger.warning("Vault 경로에 '%s' 키가 없거나 비어 있습니다.", key)

    logger.info(
        "Vault 시크릿 주입 완료: %s  (경로: %s/data/%s)",
        injected, VAULT_MOUNT, VAULT_PATH,
    )
