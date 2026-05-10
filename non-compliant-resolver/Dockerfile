FROM python:3.12-slim

WORKDIR /app
RUN pip install --no-cache-dir dnslib==0.9.25

COPY non_compliant.py .

ENV NON_COMPLIANT_BEHAVIOR=servfail
EXPOSE 53/udp 53/tcp

CMD ["python", "non_compliant.py"]
