FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    file \
    binutils \
    unzip \
    p7zip-full \
    poppler-utils \
    && rm -rf /var/lib/apt/lists/*

COPY inspect_attachment.sh /usr/local/bin/inspect_attachment.sh

RUN chmod 755 /usr/local/bin/inspect_attachment.sh

ENTRYPOINT ["/usr/local/bin/inspect_attachment.sh"]
