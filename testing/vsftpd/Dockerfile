FROM ubuntu:wily

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y \
        ssl-cert \
        vsftpd

COPY image/ /

CMD ["vsftpd"]
