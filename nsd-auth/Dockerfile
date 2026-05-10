FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends nsd dnsutils inotify-tools \
    && rm -rf /var/lib/apt/lists/*

COPY nsd.conf /etc/nsd/nsd.conf
COPY zones/ /etc/nsd/zones/
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh \
    && mkdir -p /shared/zones /etc/nsd/zones/dynamic \
    && touch /shared/zones-dynamic.conf /shared/reload-trigger.txt

EXPOSE 53/udp 53/tcp

ENTRYPOINT ["/entrypoint.sh"]
