FROM debian:bullseye-slim AS builder

ARG DNSMASQ_VERSION=2.82

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential ca-certificates wget \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

RUN wget -O dnsmasq.tar.gz "https://thekelleys.org.uk/dnsmasq/dnsmasq-${DNSMASQ_VERSION}.tar.gz" \
    && tar xzf dnsmasq.tar.gz \
    && make -C "dnsmasq-${DNSMASQ_VERSION}"

FROM debian:bullseye-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/dnsmasq-2.82/src/dnsmasq /usr/sbin/dnsmasq
COPY dnsmasq.conf /etc/dnsmasq.conf

EXPOSE 53/udp 53/tcp

CMD ["dnsmasq", "--keep-in-foreground", "--conf-file=/etc/dnsmasq.conf"]

