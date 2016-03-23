FROM ubuntu:wily

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y \
        nginx \
        ssl-cert \
 && ln -sf /dev/stdout /var/log/nginx/access.log \
 && ln -sf /dev/stderr /var/log/nginx/error.log \
 && dd if=/dev/urandom of=/var/www/html/data.dat bs=1M count=16 \
 && true

COPY image/ /

CMD ["nginx", "-g", "daemon off;"]
