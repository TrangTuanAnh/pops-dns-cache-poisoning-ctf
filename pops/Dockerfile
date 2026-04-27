FROM python:3.12-slim

WORKDIR /app

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh \
    && mkdir -p /var/log/pops

VOLUME ["/var/log/pops"]

ENTRYPOINT ["/entrypoint.sh"]

