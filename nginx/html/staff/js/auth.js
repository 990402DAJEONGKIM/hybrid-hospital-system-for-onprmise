// by 김다정 — JWT 관리 및 역할 체크 공통 모듈 (웹 구조도 반영)
// script.js의 apiCall/logout을 의존하므로 반드시 script.js 이후에 로드할 것

const STAFF_ROLES = ['doctor', 'nurse', 'admin'];

// 현재 로그인 사용자 정보를 반환. 미인증 시 login.html 리다이렉트.
async function getMyInfo() {
    const res = await apiCall('/auth/me');
    if (!res || !res.ok) {
        window.location.href = resolveRoot('login.html');
        return null;
    }
    return res.json();
}

// 허용 역할 배열을 받아 해당 역할이 아니면 index.html로 리다이렉트.
// 백엔드 인가와 별개로 UX 목적의 역할 체크 — 실제 보안은 백엔드 role_permissions에서 수행.
async function requireRole(allowedRoles) {
    const me = await getMyInfo();
    if (!me) return null;
    if (!allowedRoles.includes(me.role)) {
        window.location.href = resolveRoot('index.html');
        return null;
    }
    if (me.password_expired) {
        window.location.href = resolveRoot('change-password.html');
        return null;
    }
    return me;
}

// 포털 서브디렉토리(/nurse/, /doctor/ 등) 내에서 루트 상대경로 반환
function resolveRoot(path) {
    // 현재 URL의 첫 번째 경로 세그먼트(포털 디렉토리)를 추출
    const match = window.location.pathname.match(/^\/([^/]+)\//);
    if (match) return '/' + match[1] + '/' + path;
    return '/' + path;
}
