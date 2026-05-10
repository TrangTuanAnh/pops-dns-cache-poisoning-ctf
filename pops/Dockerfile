FROM python:3.12-slim

# tcpdump cho debug, libpcap cho scapy AsyncSniffer, iproute2 cho tc netem khi
# stage 1 áp delay artificial.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        tcpdump libpcap0.8 iproute2 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# dnslib cho parse/build DNS message; scapy cho fragment sniffer (optional).
RUN pip install --no-cache-dir dnslib==0.9.25 scapy==2.5.0

COPY source/ /app/
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh \
    && mkdir -p /var/log/pops

VOLUME ["/var/log/pops"]

EXPOSE 53/udp 53/tcp 8080/tcp

ENTRYPOINT ["/entrypoint.sh"]
