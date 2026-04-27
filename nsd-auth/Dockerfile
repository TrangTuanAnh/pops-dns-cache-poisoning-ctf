FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends nsd dnsutils \
    && rm -rf /var/lib/apt/lists/*

COPY nsd.conf /etc/nsd/nsd.conf
COPY zones/ /etc/nsd/zones/

EXPOSE 53/udp 53/tcp

CMD ["nsd", "-d", "-c", "/etc/nsd/nsd.conf"]

