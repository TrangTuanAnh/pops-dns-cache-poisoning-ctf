# Technitium DNS Server v7.0 - vulnerable cho CVE-2021-43105.
# Image official tu Docker Hub: technitium/dns-server:7.0
# Fixed trong v8.0+. Khong deploy version nay trong production.
#
# Pin digest neu image bi xoa khoi Docker Hub: copy tarball ve local va
# load qua `docker load -i technitium-7.0.tar`, sau do thay FROM bang
# tag local.
FROM technitium/dns-server:7.0

# Image official (Debian Buster) khong co curl. Buster da archived nen
# can chuyen apt sources sang archive.debian.org truoc khi install.
USER root
RUN printf "deb [trusted=yes check-valid-until=no] http://archive.debian.org/debian buster main\ndeb [trusted=yes check-valid-until=no] http://archive.debian.org/debian-security buster/updates main\n" > /etc/apt/sources.list \
    && apt-get update -o Acquire::Check-Valid-Until=false \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# entrypoint custom de configure conditional forwarder qua POPS upstream
# va seed cac zone can thiet.
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 53/udp 53/tcp 5380/tcp

ENTRYPOINT ["/entrypoint.sh"]
