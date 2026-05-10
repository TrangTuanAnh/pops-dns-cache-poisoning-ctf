FROM debian:stretch-slim AS builder

# Debian Stretch ship voi glibc 2.24, vulnerable cho CVE-2017-12132.
# Stretch da archived: dung snapshot.debian.org cho APT repo on dinh.
RUN printf "deb [trusted=yes check-valid-until=no] http://archive.debian.org/debian stretch main\ndeb [trusted=yes check-valid-until=no] http://archive.debian.org/debian-security stretch/updates main\n" > /etc/apt/sources.list \
    && echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99no-check-valid \
    && apt-get update -o Acquire::Check-Valid-Until=false \
    && apt-get install -y --no-install-recommends build-essential libc6-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY resolver_wrapper.c .
# Compile voi -lresolv de link res_send tu glibc.
RUN gcc -Wall -Wextra -O2 -o resolver_wrapper resolver_wrapper.c -lresolv

FROM debian:stretch-slim
RUN printf "deb [trusted=yes check-valid-until=no] http://archive.debian.org/debian stretch main\ndeb [trusted=yes check-valid-until=no] http://archive.debian.org/debian-security stretch/updates main\n" > /etc/apt/sources.list \
    && echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99no-check-valid \
    && apt-get update -o Acquire::Check-Valid-Until=false \
    && apt-get install -y --no-install-recommends iproute2 dnsutils \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/resolver_wrapper /usr/local/bin/resolver_wrapper
COPY resolv.conf /etc/resolv.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV RESOLVER_PORT=53
EXPOSE 53/udp 53/tcp

# Verify glibc version trong build log
RUN ldd --version | head -1 || true

ENTRYPOINT ["/entrypoint.sh"]
