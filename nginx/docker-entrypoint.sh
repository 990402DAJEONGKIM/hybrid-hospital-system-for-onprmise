#!/bin/sh
set -e

if [ -z "$NGINX_API_KEY" ]; then
  echo "[ERROR] NGINX_API_KEY 환경변수가 설정되지 않았습니다." >&2
  exit 1
fi

# read-only 마운트라 직접 수정 불가 → 임시 디렉토리에 치환본 생성
mkdir -p /tmp/nginx
envsubst '${NGINX_API_KEY}' < /etc/nginx/nginx.conf > /tmp/nginx/nginx.conf

exec nginx -g 'daemon off;' -c /tmp/nginx/nginx.conf
