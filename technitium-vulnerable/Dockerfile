FROM alpine:3.20

RUN adduser -D -H technitium
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

USER technitium
EXPOSE 53/udp 53/tcp 5380/tcp

ENTRYPOINT ["/entrypoint.sh"]

