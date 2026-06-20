// ── API 공통 설정 — by 김다정, 2026-06-06 ─────────────────────
// BASE_URL: 온프레미스 백엔드 (staff.mzclinic.cloud nginx → FastAPI /staff/*)
// ONPREM_BASE_URL: 내부 도메인 기반 호출 URL (172.30.1.76 → staff.mzclinic.cloud 로 변경) — by 김다정, 2026-06-06
//   의사 PC hosts 파일에서 staff.mzclinic.cloud = 172.30.1.76 으로 해석됨
//   IP 직접 노출 제거 → 사설 CA 인증서 CN 과 일치하여 브라우저 경고 없음
// API_KEY: NGINX가 proxy_set_header로 주입 — 프론트엔드 노출 불필요
const BASE_URL        = '/api/staff';
const ONPREM_BASE_URL = 'https://staff.mzclinic.cloud';  // IP → 내부 도메인 — by 김다정, 2026-06-06
const API_KEY         = '';
