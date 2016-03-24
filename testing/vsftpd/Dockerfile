FROM ubuntu:wily

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y \
        ssl-cert \
        vsftpd

RUN mkdir -p /var/run/vsftpd/empty
RUN touch /var/run/vsftpd/empty/foobs

COPY image/ /

EXPOSE 20 21

CMD ["vsftpd"]
