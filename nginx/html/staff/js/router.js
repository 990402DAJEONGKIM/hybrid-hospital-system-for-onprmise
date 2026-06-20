// router.js — SPA 라우터
// layout.js가 sidebar click 핸들러에서 loadPage()를 호출

async function loadPage(url) {
    const main = document.querySelector('.l-main');
    if (!main) return;

    main.innerHTML = `
        <div style="display:flex;align-items:center;justify-content:center;height:200px;color:#94a3b8;">
            <div style="text-align:center;">
                <i class="fas fa-spinner fa-spin" style="font-size:28px;margin-bottom:12px;display:block;"></i>
                로딩 중...
            </div>
        </div>`;

    try {
        const res = await fetch(url, { credentials: 'include' });
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const html = await res.text();
        const doc  = new DOMParser().parseFromString(html, 'text/html');

        // 이전 페이지에서 주입된 <style> 태그 제거
        document.querySelectorAll('style[data-spa]').forEach(function(el) { el.remove(); });

        // 현재 페이지의 <head style> 태그를 document.head 에 주입
        doc.querySelectorAll('head style').forEach(function(s) {
            var el = document.createElement('style');
            el.textContent = s.textContent;
            el.setAttribute('data-spa', '1');
            document.head.appendChild(el);
        });

        const pc = doc.getElementById('page-content');
        main.innerHTML = '<div id="page-content">' + (pc ? pc.innerHTML : '') + '</div>';

        // 사이드바 active 상태 갱신 — 파일명만 비교
        const pageName = url.split('/').pop() || '';
        document.querySelectorAll('.sidebar-item').forEach(function(el) {
            var href = (el.getAttribute('href') || '').split('/').pop();
            el.classList.toggle('sidebar-item--active', href === pageName);
        });

        // 인라인 스크립트 실행
        doc.querySelectorAll('body > script:not([src])').forEach(function(s) {
            var code = s.textContent.trim();

            code = code.replace(
                /const\s+me\s*=\s*await\s+initLayout\(\);/,
                'const me = window._cachedMe;'
            );

            var hasDCL = false;
            code = code.replace(
                /document\.addEventListener\(\s*['"]DOMContentLoaded['"]\s*,\s*async\s*\(\s*\)\s*=>\s*\{/,
                function() { hasDCL = true; return '(async () => {'; }
            );
            if (hasDCL) {
                var li = code.lastIndexOf('});');
                if (li !== -1) code = code.slice(0, li) + '})();' + code.slice(li + 3);
            }

            var exposed = [];
            var fnRe = /(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(/g;
            var fm;
            while ((fm = fnRe.exec(code)) !== null) {
                if (exposed.indexOf(fm[1]) === -1) exposed.push(fm[1]);
            }
            var exposeCode = exposed.map(function(n) {
                return 'if (typeof ' + n + ' === "function") window.' + n + ' = ' + n + ';';
            }).join('\n');

            code = '(() => {\n' + code + '\n' + exposeCode + '\n})();';

            var el = document.createElement('script');
            el.textContent = code;
            document.body.appendChild(el);
            document.body.removeChild(el);
        });

        history.pushState({ page: url }, '', url);

    } catch (err) {
        main.innerHTML = '<div style="padding:40px;text-align:center;color:#dc2626;"><i class="fas fa-exclamation-triangle" style="font-size:24px;margin-bottom:8px;display:block;"></i>페이지를 불러올 수 없습니다.</div>';
    }
}

window.addEventListener('popstate', function(e) {
    if (e.state && e.state.page) loadPage(e.state.page);
});
