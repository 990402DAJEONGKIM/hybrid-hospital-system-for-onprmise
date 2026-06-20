// ── mzclinic.cloud → staff.mzclinic.cloud JWT 해시 수신 — by 김다정, 2026-06-06 ──
// 의사가 AWS 외부 페이지에서 로그인 후 URL 해시(#access_token=...)에 JWT를 담아 이동.
// 해시는 서버로 전송되지 않아 로그에 노출되지 않음.
// 수신한 토큰을 httpOnly 불가 대신 이 도메인 쿠키로 설정 후 해시 제거.
(function _ingestHashToken() {
    if (!window.location.hash) return;
    const params = new URLSearchParams(window.location.hash.slice(1));
    const token  = params.get('access_token');
    if (!token) return;
    // SameSite=Strict: 외부에서 직접 쿠키 전송 차단, Secure: HTTPS 전용
    const maxAge = 1800; // ACCESS_TOKEN_EXPIRE_SECONDS 와 동일
    document.cookie = `access_token=${encodeURIComponent(token)}; path=/; max-age=${maxAge}; secure; samesite=strict`;
    // 해시 제거 — 브라우저 히스토리에 토큰 남지 않도록 — by 김다정, 2026-06-06
    history.replaceState(null, '', window.location.pathname + window.location.search);
})();

// ── 인증 기준 URL ─────────────────────────────────────────
// ONPREM_BASE_URL 설정 시: 온프레미스에서 로그인·인증 처리 (병원 내부망)
// 미설정 시: AWS 백엔드로 폴백
const AUTH_BASE = ONPREM_BASE_URL || BASE_URL;
const _authHeaders = ONPREM_BASE_URL
    ? { 'Content-Type': 'application/json' }
    : { 'Content-Type': 'application/json', 'X-API-Key': API_KEY };

// ── 공통 fetch 옵션 ────────────────────────────────────────
const _fetchDefaults = {
    credentials: 'include',
    headers: { 'Content-Type': 'application/json', 'X-API-Key': API_KEY },
};

// ── 온프레미스 경로 번역 테이블 ──────────────────────────────
// ONPREM_BASE_URL 설정 시 apiCall()이 이 매핑을 통해 경로를 자동 변환.
// AWS combined backend 경로 → 온프레미스 FastAPI 경로
const _ONPREM_PATH_MAP = [
    // ── /emr/nurse/* ──────────────────────────────────────
    ['/emr/nurse/patients/names-by-hashes',   '/portal/patients/names-by-hashes'],
    ['/emr/nurse/patients/search',             '/portal/nurse/patients/search'],
    ['/emr/nurse/patients/',                   '/portal/patients/'],      // verify, diagnoses 등
    ['/emr/nurse/encounters/',                 '/portal/encounters/'],    // discharge 등
    // ── /emr/doctor/* ─────────────────────────────────────
    ['/emr/doctor/admissions/',                '/staff/emr/doctor/admissions/'],  // 퇴원 지시 (슬래시 포함)
    ['/emr/doctor/admissions',                 '/staff/emr/doctor/admissions'],   // 입원 환자 목록
    ['/emr/doctor/patients/search',            '/staff/emr/doctor/patients/search'],
    ['/emr/doctor/patients/',                  '/staff/emr/doctor/patients/'],
    ['/emr/doctor/patients',                   '/staff/emr/doctor/patients'],    // 목록 조회 (슬래시 없음)
    ['/emr/doctor/encounters',                 '/staff/emr/doctor/encounters'],
    // ── /emr/* (기타 공통) ─────────────────────────────────
    ['/emr/departments',                       '/portal/departments'],
    ['/emr/encounters',                        '/portal/encounters'],
    ['/emr/patients/by-hash/',                 '/portal/patients/'],  // 구체적인 것 먼저
    ['/emr/patients/',                         '/portal/patients/'],
    // ── /portal/doctor/staff/* → /portal/* ────────────────
    ['/portal/doctor/staff/departments',       '/portal/departments'],
    ['/portal/doctor/staff/doctors',           '/portal/doctors'],
    ['/portal/doctor/staff/wards',             '/portal/wards'],
    ['/portal/doctor/staff/appointments',      '/portal/staff/appointments'],
    // ── /portal/doctor/* 특수 경로 ───────────────────────
    ['/portal/doctor/schedule',                '/portal/doctor/schedule'],
    ['/portal/doctor/appointment-types',       '/portal/appointment-types'],
    // ── /portal/doctor/nurse/* ───────────────────────────
    ['/portal/doctor/nurse/patients/',         '/portal/patients/'],     // reception-info 등
    // ── /admin/* → /staff/admin/* ────────────────────────
    ['/admin/',                                '/staff/admin/'],
];

function _toOnpremPath(path) {
    // 쿼리스트링 분리
    const qIdx = path.indexOf('?');
    const base  = qIdx >= 0 ? path.slice(0, qIdx) : path;
    const query = qIdx >= 0 ? path.slice(qIdx) : '';

    // ── 정규식이 필요한 특수 케이스 ───────────────────────────
    // /portal/doctor/patients/${hash} (단건 hash 조회) → /portal/patients/${hash}
    const byHashM = base.match(/^\/portal\/doctor\/patients\/([^/]+)$/);
    if (byHashM && byHashM[1] !== 'search') {
        return `/portal/patients/${byHashM[1]}${query}`;
    }
    // /portal/doctor/appointments/today → staff 백엔드 RDS 예약 목록 (mode=today|week 지원)
    if (base === '/portal/doctor/appointments/today') {
        return '/staff/portal/doctor/appointments/today' + query;
    }

    // ── 문자열 prefix 치환 (순서 중요: 구체적인 것 먼저) ─────
    for (const [from, to] of _ONPREM_PATH_MAP) {
        if (base.startsWith(from)) {
            return base.replace(from, to) + query;
        }
    }
    return path;
}

// ── 온프레미스 API 호출 (민감 데이터 — 병원 내부망 전용) — by 김다정, 2026-06-06 ──
// 환자 실명·진료기록·EMR 등 1등급 데이터는 이 함수로 온프레미스를 직접 호출.
// ONPREM_BASE_URL이 빈 문자열이면 병원 내부망 접속 안내 오류를 반환.
async function onpremApiCall(path, options = {}) {
    if (!ONPREM_BASE_URL) {
        const err = new Error('병원 내부망에서만 사용 가능한 기능입니다.');
        err.isOnpremUnavailable = true;
        throw err;
    }
    try {
        const res = await fetch(`${ONPREM_BASE_URL}${path}`, {
            credentials: 'include',
            headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
            ...options,
        });
        if (res.status === 401) { logout(); return null; }
        if (res.status === 403) { _handle403(); return null; }
        if (!res.ok) {
            const body = await res.json().catch(() => ({}));
            throw new Error(body.detail || `온프레미스 API 오류 (${res.status})`);
        }
        return res;
    } catch (e) {
        if (e.isOnpremUnavailable) throw e;
        throw new Error('병원 내부망에서만 사용 가능한 기능입니다.');
    }
}

async function _refreshTokens() {
    try {
        // 온프레미스 세션 갱신 (설정된 경우)
        if (ONPREM_BASE_URL) {
            const r = await fetch(`${ONPREM_BASE_URL}/auth/refresh`, {
                method: 'POST', credentials: 'include', headers: _authHeaders,
            });
            if (!r.ok) return false;
        }
        // AWS 세션 갱신 미사용 — staff는 온프레미스 데이터만 사용 by 김다정 20260605
        // const res = await fetch(`${BASE_URL}/auth/refresh`, { method: 'POST', ..._fetchDefaults });
        // return res.ok;
        return true;
    } catch { return false; }
}

// ── 접근 거부 처리 — by 김다정, 2026-06-06 ───────────────────
// 403 응답 시 날것의 브라우저 에러 대신 오버레이로 안내 후 2.5초 뒤 홈 이동
function _handle403() {
    const overlay = document.createElement('div');
    overlay.style.cssText = [
        'position:fixed;inset:0;background:rgba(0,0,0,.45);',
        'z-index:9999;display:flex;align-items:center;justify-content:center;',
    ].join('');
    overlay.innerHTML = `
        <div style="background:#fff;border-radius:12px;padding:40px 48px;text-align:center;max-width:380px;box-shadow:0 8px 32px rgba(0,0,0,.18);">
            <div style="width:56px;height:56px;border-radius:50%;background:#fee2e2;display:flex;align-items:center;justify-content:center;margin:0 auto 20px;">
                <svg width="28" height="28" fill="none" viewBox="0 0 24 24" stroke="#dc2626" stroke-width="2">
                    <rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
                </svg>
            </div>
            <h2 style="font-size:18px;font-weight:700;color:#111827;margin-bottom:8px;">접근 권한이 없습니다</h2>
            <p style="font-size:14px;color:#6b7280;line-height:1.6;">이 페이지에 대한 접근 권한이 없습니다.<br>잠시 후 메인 화면으로 이동합니다.</p>
        </div>`;
    document.body.appendChild(overlay);
    setTimeout(() => { window.location.href = '/'; }, 2500);
}

// ── 세션 만료 경고 배너 ──────────────────────────────────────
let _sessionWarnShown = false;

function _showSessionWarning(remaining) {
    if (_sessionWarnShown) return;
    _sessionWarnShown = true;
    const mins = Math.ceil(remaining / 60);
    let banner = document.getElementById('_sessionWarnBanner');
    if (!banner) {
        banner = document.createElement('div');
        banner.id = '_sessionWarnBanner';
        banner.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:9999;background:#ff9800;color:#fff;text-align:center;padding:10px 16px;font-weight:bold;font-size:14px;';
        banner.innerHTML = `세션이 약 ${mins}분 후 만료됩니다.
            <button onclick="extendSession()" style="margin-left:12px;padding:4px 14px;background:#fff;color:#ff9800;border:none;border-radius:4px;font-weight:bold;cursor:pointer;">세션 연장</button>`;
        document.body.prepend(banner);
    }
}

async function extendSession() {
    const ok = await _refreshTokens();
    if (ok) {
        _sessionWarnShown = false;
        const b = document.getElementById('_sessionWarnBanner');
        if (b) b.remove();
    } else {
        logout();
    }
}

async function apiCall(path, options = {}) {
    // ONPREM_BASE_URL 설정 시: 온프레미스로 라우팅 (모든 DB 호출)
    // 미설정 시: AWS 백엔드 폴백
    const useOnprem = !!ONPREM_BASE_URL;
    const base      = useOnprem ? ONPREM_BASE_URL : BASE_URL;
    const translated = useOnprem ? _toOnpremPath(path) : path;
    const headers   = useOnprem
        ? { 'Content-Type': 'application/json', ...(options.headers || {}) }
        : { ..._fetchDefaults.headers, ...(options.headers || {}) };

    const res = await fetch(`${base}${translated}`, {
        credentials: 'include',
        ...options,
        headers,
    });

    if (res && res.headers.get('X-Session-Expiring-Soon') === 'true') {
        _showSessionWarning(parseInt(res.headers.get('X-Session-Remaining-Seconds') || '300'));
    }
    if (res.status === 401) {
        const ok = await _refreshTokens();
        if (!ok) { logout(); return null; }
        return fetch(`${base}${translated}`, {
            credentials: 'include',
            ...options,
            headers,
        });
    }
    if (res.status === 403) { _handle403(); return null; }
    return res;
}

async function logout() {
    try {
        // AWS 로그아웃 미사용 — staff는 온프레미스 데이터만 사용 by 김다정 20260605
        // await fetch(`${BASE_URL}/auth/logout`, { method: 'POST', ..._fetchDefaults });
        if (ONPREM_BASE_URL) {
            fetch(`${ONPREM_BASE_URL}/auth/logout`, {
                method: 'POST', credentials: 'include', headers: _authHeaders,
            }).catch(() => {});
        }
    } catch {}
    window.location.href = 'login.html';
}

// ── 페이지별 역할 진입 제한 — by 김다정, 2026-06-06 ──────────
// 사용법: const me = await requireRole(['doctor']);
// 허용되지 않은 role 접근 시 _handle403() 호출 → 오버레이 표시
async function requireRole(allowedRoles) {
    const me = await requireLogin();
    if (!me) return null;
    if (!allowedRoles.includes(me.role)) {
        _handle403();
        return null;
    }
    return me;
}

async function requireLogin() {
    // AUTH_BASE: 온프레미스 설정 시 온프레미스 /auth/me, 아니면 AWS
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
    return me;
}

// ── DOMContentLoaded ──────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {

    const me = await requireLogin();
    if (!me) return;

    const header           = document.querySelector('.sass-header');
    const mobileMenuBtn    = document.getElementById('sassMobileMenuBtn');
    const mobileMenuClose  = document.getElementById('sassMobileMenuClose');
    const mobileMenu       = document.getElementById('sassMobileMenu');
    const overlay          = document.getElementById('sassOverlay');

    const appointmentSection       = document.getElementById('appointment-section');
    const patientManagementSection = document.getElementById('patient-management-section');
    const hospitalIntroSection     = document.getElementById('hospital-intro-section');
    const calendarGridContainer    = document.querySelector('.calendar-grid-container');
    const calendarGrid             = document.getElementById('calendar-grid');
    const monthYearDisplay         = document.getElementById('currentMonthYear');
    const prevMonthBtn             = document.getElementById('prevMonth');
    const nextMonthBtn             = document.getElementById('nextMonth');
    const calendarModal            = document.getElementById('calendarModal');
    const modalDateHeader          = document.getElementById('modalDateHeader');
    const modalAppointmentList     = document.getElementById('modalAppointmentList');
    const closeCalendarModal       = document.getElementById('closeCalendarModal');
    const modalConfirmBtn          = document.getElementById('modalConfirmBtn');

    const navHome                     = document.getElementById('nav-home');
    const mobileNavHome               = document.getElementById('mobile-nav-home');
    const navHospitalIntro            = document.getElementById('nav-hospital-intro');
    const mobileNavHospitalIntro      = document.getElementById('mobile-nav-hospital-intro');
    const navDoctorAppointmentsStatus = document.getElementById('nav-doctor-appointments-status');
    const navPatientInfoManagement    = document.getElementById('nav-patient-info-management');
    const logoutBtn                   = document.getElementById('logoutBtn');
    const userWelcomeItem             = document.getElementById('userWelcomeItem');
    const userWelcome                 = document.getElementById('userWelcome');

    const patientTableBody    = document.getElementById('patientTableBody');
    const patientSearchInput  = document.getElementById('patientSearchInput');
    const patientSearchBtn    = document.getElementById('patientSearchBtn');

    const patientDetailModal      = document.getElementById('patientDetailModal');
    const closePatientDetailModal = document.getElementById('closePatientDetailModal');
    const closePatientDetailBtn   = document.getElementById('closePatientDetailBtn');
    const patientAgeInput         = document.getElementById('patientAge');
    const patientDiagnosisInput   = document.getElementById('patientDiagnosis');

    // ── 헤더 ────────────────────────────────────────────────
    window.addEventListener('scroll', () => {
        if (header) header.classList.toggle('sass-header-scrolled', window.scrollY > 50);
    });
    const toggleMenu = () => {
        mobileMenu.classList.toggle('sass-active');
        overlay.classList.toggle('sass-active');
        document.body.style.overflow = mobileMenu.classList.contains('sass-active') ? 'hidden' : '';
    };
    if (mobileMenuBtn)   mobileMenuBtn.addEventListener('click', toggleMenu);
    if (mobileMenuClose) mobileMenuClose.addEventListener('click', toggleMenu);
    if (overlay)         overlay.addEventListener('click', toggleMenu);

    if (userWelcome)     userWelcome.textContent = `${me.role} 님 환영합니다`;
    if (userWelcomeItem) userWelcomeItem.classList.remove('hidden');
    if (logoutBtn)       logoutBtn.classList.remove('hidden');
    if (logoutBtn)       logoutBtn.addEventListener('click', logout);

    // ── 달력 (의료진 — 전체 예약현황 조회) ─────────────────
    let currentDate   = new Date();
    let appointmentsMap = {};

    const STATUS_LABEL = {
        pending: '대기', confirmed: '확정',
        cancelled: '취소', completed: '완료', no_show: '미내원',
    };
    let DEPT_LABEL = {};
    apiCall('/portal/doctor/staff/departments').then(r => r && r.ok && r.json()).then(list => {
        if (list) list.forEach(d => { DEPT_LABEL[d.department_code] = d.department_name; });
    }).catch(() => {});

    async function loadAppointments() {
        appointmentsMap = {};
        try {
            const res = await apiCall('/portal/doctor/schedule');
            if (!res || !res.ok) return;
            const list = await res.json();
            list.forEach(appt => {
                const date = appt.appointment_date;
                if (!appointmentsMap[date]) appointmentsMap[date] = [];
                appointmentsMap[date].push(appt);
            });
        } catch {}
    }

    const renderCalendar = () => {
        if (!calendarGrid) return;
        calendarGrid.innerHTML = '';
        const year  = currentDate.getFullYear();
        const month = currentDate.getMonth();
        monthYearDisplay.innerText = `${year}년 ${month + 1}월`;
        const firstDay    = new Date(year, month, 1).getDay();
        const daysInMonth = new Date(year, month + 1, 0).getDate();
        const numWeeks    = Math.ceil((firstDay + daysInMonth) / 7);
        if (calendarGridContainer) calendarGridContainer.style.gridTemplateRows = `auto repeat(${numWeeks}, 1fr)`;
        const today       = new Date();
        const isThisMonth = today.getFullYear() === year && today.getMonth() === month;

        for (let i = 0; i < firstDay; i++) {
            const empty = document.createElement('div');
            empty.className = 'bg-gray-50/50 min-h-[120px] border-b border-r border-gray-100';
            calendarGrid.appendChild(empty);
        }
        for (let day = 1; day <= daysInMonth; day++) {
            const dateString = `${year}-${String(month + 1).padStart(2, '0')}-${String(day).padStart(2, '0')}`;
            const dayOfWeek  = new Date(year, month, day).getDay();
            const dayCell    = document.createElement('div');
            dayCell.className = 'calendar-day';
            if (dayOfWeek === 0) dayCell.classList.add('is-sunday');
            if (dayOfWeek === 6) dayCell.classList.add('is-saturday');
            if (isThisMonth && today.getDate() === day) dayCell.classList.add('is-today');
            dayCell.innerHTML = `<span class="day-number">${day}</span>`;
            const appts = appointmentsMap[dateString];
            if (appts && appts.length > 0) {
                const badge = document.createElement('div');
                badge.className = 'mt-1 w-full text-[10px] px-2 py-1 bg-blue-100 text-blue-700 rounded-md font-bold truncate';
                badge.innerText = `예약 ${appts.length}건`;
                dayCell.appendChild(badge);
            }
            dayCell.addEventListener('click', () => showAppointments(dateString));
            calendarGrid.appendChild(dayCell);
        }
    };

    const showAppointments = (date) => {
        modalDateHeader.innerText = date;
        modalAppointmentList.innerHTML = '';
        const appts = appointmentsMap[date];
        if (appts && appts.length > 0) {
            appts.forEach(appt => {
                const item = document.createElement('div');
                item.className = 'p-3 bg-blue-50 border-l-4 border-blue-500 text-blue-800 text-sm rounded';
                const deptLabel   = DEPT_LABEL[appt.department_code] || appt.department_code;
                const statusLabel = STATUS_LABEL[appt.status_code]   || appt.status_code;
                item.innerText = `${deptLabel} · ${statusLabel} | 환자 ${appt.patient_id_hash?.slice(0, 8) || '-'}…`;
                modalAppointmentList.appendChild(item);
            });
        } else {
            modalAppointmentList.innerHTML = '<p class="text-gray-500 text-center py-4">해당 날짜에 예약 내역이 없습니다.</p>';
        }
        calendarModal.classList.remove('hidden');
        calendarModal.classList.add('flex');
        document.body.style.overflow = 'hidden';
    };

    const hideModal = () => {
        calendarModal.classList.add('hidden');
        calendarModal.classList.remove('flex');
        document.body.style.overflow = '';
    };

    if (prevMonthBtn)       prevMonthBtn.addEventListener('click', () => { currentDate.setMonth(currentDate.getMonth() - 1); renderCalendar(); });
    if (nextMonthBtn)       nextMonthBtn.addEventListener('click', () => { currentDate.setMonth(currentDate.getMonth() + 1); renderCalendar(); });
    if (closeCalendarModal) closeCalendarModal.addEventListener('click', hideModal);
    if (modalConfirmBtn)    modalConfirmBtn.addEventListener('click', hideModal);

    // ── 환자 목록 ────────────────────────────────────────────
    let patientsList = [];

    async function loadPatients() {
        try {
            const res = await apiCall('/portal/doctor/patients');
            if (!res || !res.ok) return;
            patientsList = await res.json();
        } catch { patientsList = []; }
    }

    const GENDER_LABEL = { M: '남', F: '여' };

    const renderPatientList = (query = '') => {
        const filtered = patientsList.filter(p =>
            p.patient_id_hash.includes(query) || String(p.birth_year).includes(query)
        );
        patientTableBody.innerHTML = filtered.map(p => `
            <tr class="bg-white border-b hover:bg-gray-50">
                <td class="px-4 py-3 font-mono text-xs text-gray-500">${p.patient_id_hash}</td>
                <td class="px-4 py-3">${p.birth_year}년생</td>
                <td class="px-4 py-3">${GENDER_LABEL[p.gender_code] || p.gender_code}</td>
                <td class="px-4 py-3">${p.last_visit || '-'}</td>
                <td class="px-4 py-3">
                    <button onclick="viewPatientDetail('${p.patient_id_hash}')"
                        class="px-2 py-1 bg-blue-50 text-blue-600 border border-blue-200 rounded text-xs font-bold hover:bg-blue-100 transition-colors">
                        상세 조회
                    </button>
                </td>
            </tr>
        `).join('');
    };

    window.viewPatientDetail = async (patientIdHash) => {
        const res = await apiCall(`/portal/doctor/patients/${patientIdHash}`);
        if (!res || !res.ok) { alert('상세 정보를 불러올 수 없습니다.'); return; }
        const data = await res.json();
        const p       = data.patient;
        const allergy = data.allergies?.map(a => `${a.allergy_name}(${a.severity_code})`).join(', ') || '없음';
        const surgery = data.surgeries?.map(s => `${s.surgery_name}(${s.surgery_date})`).join(', ') || '없음';
        const diag    = data.diagnoses?.map(d => d.diagnosis_code).join(', ') || '없음';

        if (patientAgeInput)       patientAgeInput.value       = `${p.birth_year}년생`;
        if (patientDiagnosisInput) patientDiagnosisInput.value = `진단: ${diag}\n알레르기: ${allergy}\n수술: ${surgery}`;

        patientDetailModal.classList.remove('hidden');
        patientDetailModal.classList.add('flex');
        document.body.style.overflow = 'hidden';
    };

    const closePatientDetailFn = () => {
        patientDetailModal.classList.add('hidden');
        patientDetailModal.classList.remove('flex');
        document.body.style.overflow = '';
    };
    if (closePatientDetailModal) closePatientDetailModal.addEventListener('click', closePatientDetailFn);
    if (closePatientDetailBtn)   closePatientDetailBtn.addEventListener('click', closePatientDetailFn);

    if (patientSearchBtn) patientSearchBtn.addEventListener('click', () => renderPatientList(patientSearchInput.value.trim()));
    if (patientSearchInput) patientSearchInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') renderPatientList(patientSearchInput.value.trim());
    });

    // ── 섹션 전환 ───────────────────────────────────────────
    const showSection = async (sectionId) => {
        appointmentSection.classList.add('hidden');
        patientManagementSection.classList.add('hidden');
        if (hospitalIntroSection) hospitalIntroSection.classList.add('hidden');

        if (sectionId === 'patient-management') {
            patientManagementSection.classList.remove('hidden');
            await loadPatients();
            renderPatientList();
        } else if (sectionId === 'hospital-intro') {
            if (hospitalIntroSection) hospitalIntroSection.classList.remove('hidden');
        } else {
            appointmentSection.classList.remove('hidden');
            await loadAppointments();
            renderCalendar();
        }
    };

    const closeMenuIfOpen = () => {
        if (mobileMenu.classList.contains('sass-active')) toggleMenu();
    };

    if (navDoctorAppointmentsStatus) navDoctorAppointmentsStatus.addEventListener('click', async (e) => { e.preventDefault(); await showSection('calendar'); closeMenuIfOpen(); });
    if (navPatientInfoManagement)    navPatientInfoManagement.addEventListener('click', async (e) => { e.preventDefault(); await showSection('patient-management'); closeMenuIfOpen(); });
    if (navHome)                     navHome.addEventListener('click', async (e) => { e.preventDefault(); await showSection('calendar'); closeMenuIfOpen(); });
    if (mobileNavHome)               mobileNavHome.addEventListener('click', async (e) => { e.preventDefault(); await showSection('calendar'); closeMenuIfOpen(); });
    if (navHospitalIntro)            navHospitalIntro.addEventListener('click', (e) => { e.preventDefault(); showSection('hospital-intro'); closeMenuIfOpen(); });
    if (mobileNavHospitalIntro)      mobileNavHospitalIntro.addEventListener('click', (e) => { e.preventDefault(); showSection('hospital-intro'); closeMenuIfOpen(); });

    // ── 초기 로드 (calendar-grid가 있는 페이지에서만 실행) ───
    if (calendarGrid) {
        await loadAppointments();
        renderCalendar();
    }
});

