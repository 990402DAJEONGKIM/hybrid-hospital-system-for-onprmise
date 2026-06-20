let sessionTimeout;
const EXPIRE_TIME = 1800 * 1000; // 30분
const WARNING_TIME = 300 * 1000; // 5분 전

function startSessionTimer() {
    clearTimeout(sessionTimeout);
    sessionTimeout = setTimeout(() => {
        if (confirm("세션이 5분 후 만료됩니다. 연장하시겠습니까?")) {
            extendSession();
        }
    }, EXPIRE_TIME - WARNING_TIME);
}

async function extendSession() {
    const res = await fetch(`${CONFIG.API_BASE_URL}/auth/refresh`, { method: 'POST', credentials: 'include' });
    if (res.ok) {
        alert("세션이 연장되었습니다.");
        startSessionTimer();
    } else {
        location.href = 'login.html';
    }
}