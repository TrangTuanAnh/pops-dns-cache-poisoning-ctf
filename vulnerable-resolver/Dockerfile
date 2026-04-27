FROM debian:bookworm-slim AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY resolver_wrapper.c .
RUN gcc -Wall -Wextra -O2 -o resolver_wrapper resolver_wrapper.c

FROM debian:bookworm-slim

COPY --from=builder /src/resolver_wrapper /usr/local/bin/resolver_wrapper

ENV RESOLVER_TARGET=fragment.meridian-stage2.example
ENV RESOLVER_INTERVAL=10

CMD ["resolver_wrapper"]

