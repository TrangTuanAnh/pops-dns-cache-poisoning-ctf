#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void resolve_once(const char *target) {
    struct addrinfo hints;
    struct addrinfo *result = NULL;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int rc = getaddrinfo(target, NULL, &hints, &result);
    if (rc != 0) {
        fprintf(stderr, "resolve target=%s error=%s\n", target, gai_strerror(rc));
        return;
    }

    printf("resolved target=%s\n", target);
    freeaddrinfo(result);
}

int main(void) {
    const char *target = getenv("RESOLVER_TARGET");
    const char *interval_raw = getenv("RESOLVER_INTERVAL");
    int interval = interval_raw == NULL ? 10 : atoi(interval_raw);

    if (target == NULL || target[0] == '\0') {
        target = "fragment.meridian-stage2.example";
    }
    if (interval <= 0) {
        interval = 10;
    }

    printf("glibc resolver scaffold target=%s interval=%d\n", target, interval);
    fflush(stdout);

    while (1) {
        resolve_once(target);
        fflush(stdout);
        sleep((unsigned int)interval);
    }

    return 0;
}

