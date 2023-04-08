FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive
ENV HOME=/tmp
ENV PWD=/tmp

COPY ubuntu-preseed-iso-generator.sh /usr/bin/ubuntu-preseed-iso-generator.sh

RUN chmod +x /usr/bin/ubuntu-preseed-iso-generator.sh

RUN rm -rf /var/cache/apt/archives/ && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p /var/cache/apt/archives/ && \
    mkdir -p /var/cache/apt/archives/partial/ && \
    touch /var/cache/apt/archives/lock && \
    apt-get -y autoremove && \
    apt-get -y clean && \
    apt-get -y autoclean && \
    apt-get update && \
    apt-get install --install-recommends --yes \
        dirmngr &&\
    apt-get install --no-install-recommends --yes \
        ca-certificates \
        git \
        xorriso \
        sed \
        curl \
        gpg \
        isolinux

ENTRYPOINT [ "ubuntu-preseed-iso-generator.sh" ]
