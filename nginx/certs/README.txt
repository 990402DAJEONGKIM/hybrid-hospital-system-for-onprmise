# SSL 인증서 설정 가이드
# nginx/certs/ 디렉토리에 인증서 파일이 필요해요.

# ── 개발/내부망 환경 — 자체 서명 인증서 생성 ─────────────────
# 아래 명령어를 nginx/certs/ 디렉토리에서 실행하세요.

openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout server.key \
  -out server.crt \
  -subj "/CN=deident-api/O=Hospital/C=KR"

# ── 운영 환경 — 공인 인증서 ──────────────────────────────────
# 내부망 전용이므로 사설 CA(Certificate Authority) 발급 인증서 권장.
# 회사 내부 CA가 있으면 거기서 발급받아 server.crt, server.key로 저장.

# 파일 위치 확인
# nginx/certs/server.crt  ← 인증서
# nginx/certs/server.key  ← 개인키 (외부 유출 금지)
