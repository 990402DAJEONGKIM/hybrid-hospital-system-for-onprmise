// layout.js — 통합 직원 포털 공통 레이아웃
// 각 페이지의 DOMContentLoaded 에서 initLayout() 을 가장 먼저 호출할 것
// 의존: config.js, script.js (apiCall, logout)

const _ROLE_LABELS = { doctor: '의사', nurse: '간호사', admin: '관리자' };
const _ROLE_COLORS = { doctor: '#7c3aed', nurse: '#059669', admin: '#dc2626' };
const _ROLE_BG     = { doctor: '#ede9fe', nurse: '#d1fae5', admin: '#fee2e2' };

// 역할별 사이드바 바로가기 카드 (대시보드 카드와 동일 소스)
const _SHORTCUTS = {
    nurse: [
        { url:'nurse-dashboard.html',      icon:'calendar-alt',   color:'#0ea5e9', label:'예약 현황',    desc:'날짜·상태별 예약 목록' },
        { url:'nurse-appointment-new.html', icon:'plus-circle',    color:'#10b981', label:'접수',         desc:'방문 환자 직접 접수' },
        { url:'patient-register.html',      icon:'user-plus',      color:'#6366f1', label:'환자 등록',    desc:'신규 환자 등록·회원번호 발급' },
        { url:'patient-search.html',        icon:'search',         color:'#f59e0b', label:'환자 검색',    desc:'이름·회원번호로 조회' },
        { url:'ward-status.html',           icon:'hospital',       color:'#ec4899', label:'병동 현황',    desc:'병동별 가용 병상' },
        { url:'nurse-inpatients.html',      icon:'bed',            color:'#7c3aed', label:'입원 관리',    desc:'입원 환자 조회 및 퇴원 관리' },
    ],
    doctor: [
        { url:'doctor-schedule.html',    icon:'stethoscope',   color:'#0ea5e9', label:'오늘 진료',    desc:'확정된 진료 일정 확인' },
        { url:'my-patients.html',        icon:'user-injured',  color:'#6366f1', label:'내 환자 목록', desc:'담당 환자 목록 · EMR · 진료 기록' },
        { url:'doctor-admissions.html',  icon:'bed',           color:'#7c3aed', label:'입원 환자',    desc:'담당 입원 환자 조회 · 퇴원 지시' },
    ],
    admin: [
        { url:'admin-users.html',  icon:'users',      color:'#0ea5e9', label:'사용자 관리',    desc:'계정 생성·수정·잠금·비활성화' },
        { url:'admin-policy.html', icon:'lock',       color:'#6366f1', label:'보안 정책',      desc:'비밀번호 복잡도·만료 설정' },
    ],
};

async function initLayout() {
    // 인증 확인 — AUTH_BASE(온프레미스 우선) 사용
    const res = await fetch(`${AUTH_BASE}/auth/me`, {
        credentials: 'include', headers: _authHeaders,
    });
    if (!res || !res.ok) { window.location.href = 'login.html'; return null; }
    const me = await res.json();
    if (!['doctor', 'nurse', 'admin'].includes(me.role)) {
        window.location.href = 'login.html'; return null;
    }
    if (me.must_change_password || me.password_expired) {
        window.location.href = 'change-password.html'; return null;
    }
    if (!me.mfa_enabled) {
        window.location.href = 'mfa-setup.html'; return null;
    }

    // 현재 페이지 파악 (active 표시용) — 파일명만 추출
    const currentPage = window.location.pathname.split('/').pop() || 'index.html';

    // 기존 페이지 콘텐츠 추출
    const pageContent = document.getElementById('page-content');
    const contentHTML = pageContent ? pageContent.innerHTML : '';
    const pageTitle   = document.title;

    // 사이드바 — 홈 고정 항목 + 역할별 바로가기 카드
    const isDashboard = currentPage === 'index.html' || currentPage === '';
    const homeItem = '';

    const shortcuts = _SHORTCUTS[me.role] || [];
    const sidebarNav = homeItem + shortcuts.map(s => {
        const isActive = currentPage === s.url;
        const fullPage  = s.fullPage ? 'data-full-page="1"' : '';
        return `<a href="${s.url}" ${fullPage} class="sidebar-item sidebar-item--card${isActive ? ' sidebar-item--active' : ''}">
            <i class="fas fa-${s.icon}" style="color:${s.color};"></i>
            <div class="sidebar-item__texts">
                <span class="sidebar-item__label">${s.label}</span>
                <span class="sidebar-item__desc">${s.desc}</span>
            </div>
        </a>`;
    }).join('');

    // 레이아웃 주입
    document.body.className = '';
    document.body.style.cssText = '';
    document.body.innerHTML = `
        <!-- 상단 헤더 -->
        <header class="l-header">
            <div class="l-header__logo">
                <i class="fas fa-hospital-alt"></i>
                <span>김이박 클리닉</span>
            </div>
            <div class="l-header__center">
                <span class="l-header__system">통합 직원 포털</span>
            </div>
            <div class="l-header__right">
                <span class="l-user-info">
                    <i class="fas fa-user-circle"></i>
                    <strong>${me.role === 'doctor' && me.doctor_name ? me.doctor_name : me.member_number}</strong>
                    ${me.role === 'doctor' && me.department_name
                        ? `<span class="l-role-badge" style="background:#e0f2fe;color:#0369a1;">${me.department_name}</span>`
                        : ''}
                    <span class="l-role-badge"
                          style="background:${_ROLE_BG[me.role]};color:${_ROLE_COLORS[me.role]};">
                        ${_ROLE_LABELS[me.role]}
                    </span>
                </span>
                <button class="l-logout-btn" onclick="window.location.href='change-password.html'" style="margin-right:0.5rem;">
                    <i class="fas fa-key"></i> 비밀번호 변경
                </button>
                <button class="l-logout-btn" onclick="logout()">
                    <i class="fas fa-sign-out-alt"></i> 로그아웃
                </button>
            </div>
        </header>

        <!-- 본문 (사이드바 + 콘텐츠) -->
        <div class="l-body">
            <aside class="l-sidebar">
                <nav class="l-sidebar__nav">
                    ${sidebarNav}
                </nav>
            </aside>

            <main class="l-main">
                <div id="page-content">
                    ${contentHTML}
                </div>
            </main>
        </div>

        <!-- 하단 푸터 -->
        <footer class="l-footer">
            <span>© 2026 김이박 클리닉</span>
            <span>대표전화: 02-1234-5678 &nbsp;|&nbsp; 진료시간: 평일 09:00 – 18:00</span>
        </footer>
    `;

    document.title = pageTitle;

    // SPA: 사용자 정보 캐시 (router.js가 페이지 교체 시 재사용)
    window._cachedMe = me;

    // SPA: 사이드바 클릭 시 loadPage() 호출 (전체 페이지 이동 대신)
    const navEl = document.querySelector('.l-sidebar__nav');
    if (navEl) {
        navEl.addEventListener('click', function(e) {
            var item = e.target.closest('.sidebar-item');
            if (!item) return;
            var href = item.getAttribute('href');
            if (!href || href === '#') return;
            e.preventDefault();
            if (item.dataset.fullPage === '1') {
                window.location.href = href;
                return;
            }
            if (typeof loadPage === 'function') loadPage(href);
        });
    }

    return me;
}
