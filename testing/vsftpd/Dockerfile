FROM ubuntu:wily

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y \
        ssl-cert \
        vsftpd

RUN mkdir -p /var/run/vsftpd/empty \
 && mkdir -p /srv/vsftpd \
 && dd if=/dev/urandom of=/srv/vsftpd/data.dat bs=1M count=16

COPY image/ /

CMD ["vsftpd"]
