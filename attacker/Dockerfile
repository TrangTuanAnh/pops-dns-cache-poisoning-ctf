FROM python:3.11-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       dnsutils tcpdump curl iproute2 iputils-ping \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir dnslib==0.9.24 dnspython==2.6.1 requests==2.32.3

WORKDIR /app
# Khi build voi context = code/ (xem docker-compose.attacker.stage{1,2,3}.yml),
# attacker/listener.py va reference-solutions/ deu nam trong context.
# listener.py giu lai cho debug; main role hien tai la chay reference
# solutions qua docker exec.
COPY attacker/listener.py /app/listener.py
COPY reference-solutions/ /attack/

# Run sleep infinity la default - student exec script tu /attack/.
CMD ["sleep", "infinity"]
