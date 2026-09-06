#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include "badge.h"
#include "enrollment.h"

#define ADMIN_SOCKET_DIR "/tmp/taptrace"
#define ADMIN_SOCKET_PATH ADMIN_SOCKET_DIR "/admin.sock"

#define ADMIN_CODE_READ_VECTOR 1
#define ADMIN_STATUS_OK 0
#define ADMIN_STATUS_NOT_FOUND 1
#define ADMIN_REQUEST_LENGTH (1 + 4)
#define ADMIN_RESPONSE_LENGTH (1 + ACCESS_VECTOR_LENGTH)

#define TAPTRACE_PORT 9000
#define REQUEST_LENGTH (1 + 4 + ACCESS_VECTOR_LENGTH)

static int quiet_mode = 0;
static InternalResult last_result;

typedef struct {
    uint8_t opcode;
    uint32_t badge_id;
    uint8_t access_vector[ACCESS_VECTOR_LENGTH];
} Request;

typedef enum {
    RECV_COMPLETE,
    RECV_CLOSED,
    RECV_TRUNCATED,
    RECV_ERROR
} recv_status_t;

static recv_status_t recv_all(int fd, uint8_t *buffer, size_t length) {
    size_t filled = 0;
    while (filled < length) {
        ssize_t n = recv(fd, buffer + filled, length - filled, 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return RECV_ERROR;
        }
        if (n == 0) {
            return filled == 0 ? RECV_CLOSED : RECV_TRUNCATED;
        }
        filled += (size_t)n;
    }
    return RECV_COMPLETE;
}

static int send_all(int fd, const uint8_t *buffer, size_t length) {
    size_t sent = 0;
    while (sent < length) {
        ssize_t n = send(fd, buffer + sent, length - sent, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        sent += (size_t)n;
    }
    return 0;
}

static void parse_request(const uint8_t *buffer, Request *req) {
    req->opcode = buffer[0];
    uint32_t badge_id_net;
    memcpy(&badge_id_net, buffer + 1, sizeof(badge_id_net));
    req->badge_id = ntohl(badge_id_net);
    memcpy(req->access_vector, buffer + 5, ACCESS_VECTOR_LENGTH);
}

static const uint8_t RESPONSE[] = "REQUEST_PROCESSED";
#define RESPONSE_LENGTH (sizeof(RESPONSE) - 1)

static void handle_client(int client) {
    int no_delay = 1;
    if (setsockopt(client, IPPROTO_TCP, TCP_NODELAY, &no_delay, sizeof(no_delay)) < 0) {
        perror("setsockopt");
        return;
    }

    for (;;) {
        uint8_t buffer[REQUEST_LENGTH];
        recv_status_t status = recv_all(client, buffer, REQUEST_LENGTH);
        if (status == RECV_CLOSED) {
            printf("[*] client ferme\n");
            break;
        }
        if (status == RECV_TRUNCATED) {
            printf("[*] frame tronquee\n");
            break;
        }
        if (status == RECV_ERROR) {
            perror("recv");
            break;
        }

        Request req;
        parse_request(buffer, &req);
        last_result = process_enrollment_hardened(req.badge_id, req.access_vector);
        if (!quiet_mode) {
            printf("[*] request badge_id=%u : traitee\n", req.badge_id);
        }

        if (send_all(client, RESPONSE, RESPONSE_LENGTH) < 0) {
            perror("send");
            break;
        }
    }
}

static void handle_admin_client(int client) {
    for (;;) {
        uint8_t buffer[ADMIN_REQUEST_LENGTH];
        recv_status_t status = recv_all(client, buffer, ADMIN_REQUEST_LENGTH);
        if (status == RECV_CLOSED) {
            break;
        }
        if (status == RECV_TRUNCATED) {
            printf("[*] admin : frame tronquee\n");
            break;
        }
        if (status == RECV_ERROR) {
            perror("admin recv");
            break;
        }

        uint8_t opcode = buffer[0];
        uint32_t badge_id_net;
        memcpy(&badge_id_net, buffer + 1, sizeof(badge_id_net));
        badge_id_t badge_id = ntohl(badge_id_net);

        const Badge *badge = (opcode == ADMIN_CODE_READ_VECTOR) ? find_badge(badge_id) : NULL;

        uint8_t resp[ADMIN_RESPONSE_LENGTH];
        if (badge == NULL) {
            resp[0] = ADMIN_STATUS_NOT_FOUND;
            memset(resp + 1, 0, ACCESS_VECTOR_LENGTH);
        } else {
            resp[0] = ADMIN_STATUS_OK;
            memcpy(resp + 1, badge->access_vector, ACCESS_VECTOR_LENGTH);
        }

        printf("[*] admin : request badge_id=%u\n", badge_id);

        if (send_all(client, resp, ADMIN_RESPONSE_LENGTH) < 0) {
            perror("admin send");
            break;
        }
    }
}

static int init_admin_channel(void) {
    if (mkdir(ADMIN_SOCKET_DIR, 0700) < 0 && errno != EEXIST) {
        perror("mkdir");
        exit(1);
    }
    chmod(ADMIN_SOCKET_DIR, 0700);

    if (unlink(ADMIN_SOCKET_PATH) < 0 && errno != ENOENT) {
        perror("unlink");
        exit(1);
    }

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        exit(1);
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, ADMIN_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        exit(1);
    }

    if (chmod(ADMIN_SOCKET_PATH, 0600) < 0) {
        perror("chmod");
        exit(1);
    }

    if (listen(fd, 1) < 0) {
        perror("listen");
        exit(1);
    }

    printf("[*] canal interne ready : %s\n", ADMIN_SOCKET_PATH);
    return fd;
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    quiet_mode = getenv("TAPTRACE_QUIET") != NULL;

    int port = TAPTRACE_PORT;
    const char *port_override = getenv("TAPTRACE_PORT");
    if (port_override != NULL) {
        port = atoi(port_override);
    }

    printf("[!] MODE DEV : isolation uniquement procedurale\n");
    printf("[!] variante durcie : comparaison systematique des 8 octets, sans early exit\n");
    if (quiet_mode) {
        printf("[*] mode silencieux actif, aucun log par request\n");
    }

    int admin_fd = init_admin_channel();

    badge_id_t b1 = provision_badge(1);
    badge_id_t b2 = provision_badge(2);
    badge_id_t b3 = provision_badge(3);
    if (b1 == 0 || b2 == 0 || b3 == 0) {
        fprintf(stderr, "echec du provisioning\n");
        exit(1);
    }
    set_badge_status(b2, BADGE_REVOKED);
    set_badge_status(b3, BADGE_EXPIRED);
    printf("[*] badge provisionne, badge_id=%u, status actif\n", b1);
    printf("[*] badge provisionne, badge_id=%u, status revoque\n", b2);
    printf("[*] badge provisionne, badge_id=%u, status expire\n", b3);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        exit(1);
    }

    int reuse = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((uint16_t)port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        exit(1);
    }

    if (listen(fd, 1) < 0) {
        perror("listen");
        exit(1);
    }

    printf("[*] en ecoute sur 127.0.0.1:%d\n", port);

    int max_fd = fd > admin_fd ? fd : admin_fd;

    for (;;) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(fd, &read_fds);
        FD_SET(admin_fd, &read_fds);

        int ready = select(max_fd + 1, &read_fds, NULL, NULL, NULL);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("select");
            continue;
        }

        if (FD_ISSET(fd, &read_fds)) {
            int client = accept(fd, NULL, NULL);
            if (client < 0) {
                if (errno != EINTR) {
                    perror("accept");
                }
            } else {
                handle_client(client);
                close(client);
            }
        }

        if (FD_ISSET(admin_fd, &read_fds)) {
            int client = accept(admin_fd, NULL, NULL);
            if (client < 0) {
                if (errno != EINTR) {
                    perror("admin accept");
                }
            } else {
                handle_admin_client(client);
                close(client);
            }
        }
    }

    close(fd);
    return 0;
}
