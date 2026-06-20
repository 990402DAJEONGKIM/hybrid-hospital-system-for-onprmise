# 온프레미스 nginx — staff.mzclinic.cloud / admin.mzclinic.cloud 서빙 — by 김다정, 2026-06-06
FROM nginx:1.27-alpine

# Font Awesome 6.4.0 로컬 번들 다운로드 — by 김다정, 2026-06-06
# ISMS-P: 내부망 PC는 cdnjs.cloudflare.com 접근 불가(화이트리스트 차단)
# → Docker 빌드 시 번들링하여 브라우저가 로컬에서 로드하도록 처리
RUN apk add --no-cache gettext curl && \
    rm -rf /etc/nginx/conf.d/default.conf && \
    FA_BASE="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0" && \
    curl -sLf "$FA_BASE/css/all.min.css" -o /tmp/fa-all.min.css && \
    mkdir -p /tmp/webfonts && \
    for f in fa-brands-400.woff2 fa-regular-400.woff2 fa-solid-900.woff2 fa-v4compatibility.woff2; do \
        curl -sLf "$FA_BASE/webfonts/$f" -o "/tmp/webfonts/$f"; \
    done

COPY docker/nginx-onprem/nginx.conf /etc/nginx/nginx.conf.template

# 의료진·관리자 프론트엔드 빌드 복사 — by 김다정, 2026-06-06
COPY app/staff/frontend/  /var/www/html/staff/
COPY app/portal/frontend/ /var/www/html/admin/

# Font Awesome를 각 도메인 정적 디렉터리에 배치 — by 김다정, 2026-06-06
# CSS는 /css/, 웹폰트는 /webfonts/ (CSS 내 상대경로 ../webfonts/ 와 일치)
RUN cp /tmp/fa-all.min.css /var/www/html/staff/css/fa-all.min.css && \
    cp /tmp/fa-all.min.css /var/www/html/admin/css/fa-all.min.css && \
    cp -r /tmp/webfonts /var/www/html/staff/webfonts && \
    cp -r /tmp/webfonts /var/www/html/admin/webfonts

# 인증서는 Dockerfile COPY 대신 docker-compose volumes 마운트로 관리 — by 김다정, 2026-06-06

EXPOSE 80 443

CMD ["/bin/sh", "-c", "\
  envsubst '${API_KEY}' \
    < /etc/nginx/nginx.conf.template \
    > /etc/nginx/nginx.conf && \
  nginx -g 'daemon off;'"]
