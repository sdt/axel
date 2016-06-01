FROM ubuntu:xenial

# Specify a local apt mirror to speed up builds.
# eg. docker build --build-arg APT_MIRROR=http://br.archive.ubuntu.com/ubuntu/
ARG APT_MIRROR=&

RUN sed -i -e "s!http://archive\.ubuntu\.com/ubuntu/!$APT_MIRROR!" \
        /etc/apt/sources.list \
 && apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y \
        ca-certificates \
        nginx \
        polipo \
        supervisor \
        vsftpd \
 && mkdir -p /var/run/vsftpd/empty \
 && true

COPY certs/ca.pem /etc/ssl/certs/
COPY certs/axel.testing.pem /etc/ssl/private/
COPY image/ /

EXPOSE 21 80 443 990 8888 9991-9995
VOLUME /etc/ssl/certs

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/supervisord.conf"]
