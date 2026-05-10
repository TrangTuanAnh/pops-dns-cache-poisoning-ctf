FROM python:3.12-slim

WORKDIR /app

# dnslib cho passive DNS query loop (stage 1A/2A/3A).
RUN pip install --no-cache-dir dnslib==0.9.25

COPY app.py stage1.py stage2.py stage3.py ./

ENV PORT=8080
ENV STAGE=all
EXPOSE 8080

CMD ["python", "app.py"]
