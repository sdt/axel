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
 && true

COPY image/ /

CMD ["nginx", "-g", "daemon off;"]
