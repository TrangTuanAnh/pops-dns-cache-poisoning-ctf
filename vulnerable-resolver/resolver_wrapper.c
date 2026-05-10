/*
 * resolver_wrapper.c - thin DNS resolver wrapper su dung glibc res_send.
 *
 * Build voi glibc 2.24 (Debian Stretch) se ke thua CVE-2017-12132:
 * res_send advertise EDNS0 buffer 4096 byte mac dinh, lam authoritative
 * server co the tra response > MTU -> IP fragmentation. Off-path attacker
 * voi IP-ID prediction co the inject second fragment gia mao -> cache
 * poisoning.
 *
 * Wrapper:
 *  - Listen UDP :53.
 *  - Voi moi query, goi res_send forward len upstream tu /etc/resolv.conf.
 *  - Forward response back ve client.
 *
 * Khong cache: muc tieu la moi query trigger upstream lookup that, demo
 * fragmentation behavior cho stage 2.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <resolv.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define MAX_PACKET 4096

static int listen_port(void) {
    const char *p = getenv("RESOLVER_PORT");
    if (p == NULL || p[0] == '\0') {
        return 53;
    }
    return atoi(p);
}

int main(void) {
    if (res_init() != 0) {
        fprintf(stderr, "res_init failed\n");
        return 1;
    }
    _res.options |= RES_USE_EDNS0;

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }
    int one = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in server;
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons((uint16_t)listen_port());
    server.sin_addr.s_addr = INADDR_ANY;
    if (bind(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        perror("bind");
        return 1;
    }

    fprintf(stdout,
            "[resolver] glibc-based wrapper listening on udp/%d\n",
            listen_port());
    fprintf(stdout,
            "[resolver] forwarding via res_send (RES_USE_EDNS0 set)\n");
    fflush(stdout);

    signal(SIGPIPE, SIG_IGN);

    while (1) {
        unsigned char query[MAX_PACKET];
        struct sockaddr_in client;
        socklen_t client_len = sizeof(client);
        ssize_t qlen = recvfrom(sock, query, sizeof(query), 0,
                                 (struct sockaddr *)&client, &client_len);
        if (qlen <= 0) {
            if (errno == EINTR) continue;
            perror("recvfrom");
            continue;
        }

        unsigned char response[MAX_PACKET];
        int rlen = res_send(query, (int)qlen, response, (int)sizeof(response));
        if (rlen > 0) {
            sendto(sock, response, (size_t)rlen, 0,
                   (struct sockaddr *)&client, client_len);
        } else {
            fprintf(stderr,
                    "[resolver] res_send returned %d errno=%d (h_errno=%d)\n",
                    rlen, errno, h_errno);
        }
    }

    return 0;
}
