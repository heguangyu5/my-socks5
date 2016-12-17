// @see https://www.ietf.org/rfc/rfc1928.txt
// @see https://tools.ietf.org/html/rfc1929

#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <signal.h>

#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <arpa/inet.h>

#define FPRINTF(...) fprintf(logFile, __VA_ARGS__); fflush(logFile)
#ifdef DEBUG
#define FPRINTF_DEBUG(...) fprintf(logFile, __VA_ARGS__); fflush(logFile)
#else
#define FPRINTF_DEBUG(...)
#endif

#define HIGHLIGHT_START "\033[32;49;1m"
#define HIGHLIGHT_END   "\033[39;49;0m"

#define MAX_CONNS 500
#define CONN_BUF_LEN 4096
struct connBuf {
    uint16_t    expectedBytes;
    uint16_t    bufUsed;
    uint8_t     *bufp;
    uint8_t     buf[CONN_BUF_LEN];
};
struct conn {
    int             fd;
    uint32_t        expectedEvents;
    void            (*callback)(struct conn *);
    void            (*nextCallback)(struct conn *);
    struct conn     *assocConn;
    struct connBuf  *buf;
    uint8_t         blocked;
#ifdef DEBUG
    char            ip[INET_ADDRSTRLEN];
    uint16_t        port;
#endif
};

#define CMD_CONNECT         1
#define CMD_BIND            2
#define CMD_UDP_ASSOCIATE   3

#define CMD_REPLY_SUCCESS                   0
#define CMD_REPLY_GENERRAL_SOCKS_ERROR      1
#define CMD_REPLY_NOT_SUPPORTED             7
#define CMD_REPLY_ADDR_TYPE_NOT_SUPPORTED   8

#define ADDR_TYPE_IPV4       1
#define ADDR_TYPE_DOMAINNAME 3
#define ADDR_TYPE_IPV6       4

#define AUTH_METHOD_USER_PASS 2
#define AUTH_METHOD_USER_PASS_VER 1
#define AUTH_METHOD_USER_PASS_SUCCESS 0
#define AUTH_METHOD_USER_PASS_FAILED  1

#define SOCKS5_VER 5

// GLOBAL VARS
struct conn clientConnList[MAX_CONNS];
struct conn remoteConnList[MAX_CONNS];
struct connBuf bufPool[MAX_CONNS];
int         epfd;
FILE        *logFile;
char        *username;
char        *password;
uint8_t     usernameLen;
uint8_t     passwordLen;
// GLOBAL VARS END

void help()
{
    printf(
        "usage: ./my-socks5 -u username -p password [-P port] [-F] [-h]\n"
        "       -u  username, required\n"
        "       -p  password, required\n"
        "       -P  port, default 1080, should > 1024\n"
        "       -F  run in foreground\n"
        "       -h  usage info\n"
    );
}

void signal_handler(int signo)
{
    if (signo == SIGINT) {
        FPRINTF("caught SIGINT, exit\n");
    }
    if (signo == SIGTERM) {
        FPRINTF("caught SIGTERM, exit\n");
    }
    exit(0);
}

void initConns()
{
    int i;
    for (i = 0; i < MAX_CONNS; i++) {
        clientConnList[i].fd  = -1;
        clientConnList[i].buf = bufPool + i;
        remoteConnList[i].fd  = -1;
    }
}

void closeConn(struct conn *conn)
{
    if (conn->fd == -1) {
        return;
    }

    if (epoll_ctl(epfd, EPOLL_CTL_DEL, conn->fd, NULL) == -1) {
        FPRINTF("epoll_ctl del fd error: %s\n", strerror(errno));
        exit(1);
    }
    close(conn->fd);
    conn->fd = -1;
}

struct conn *getAFreeClientConn()
{
    int i;
    for (i = 0; i < MAX_CONNS; i++) {
        if (clientConnList[i].fd == -1) {
            return clientConnList + i;
        }
    }
    return NULL;
}

struct conn *getAFreeRemoteConn()
{
    int i;
    for (i = 0; i < MAX_CONNS; i++) {
        if (remoteConnList[i].fd == -1) {
            return remoteConnList + i;
        }
    }
    return NULL;
}

void resetConnBuf(struct connBuf *connBuf)
{
    connBuf->expectedBytes = 0;
    connBuf->bufUsed = 0;
    connBuf->bufp    = NULL;
}

void readN(struct conn *conn)
{
    struct connBuf *connBuf = conn->buf;

    int n = read(conn->fd, connBuf->buf + connBuf->bufUsed, connBuf->expectedBytes);

    // CONN_BUF_LEN means read as much as possible
    if (connBuf->expectedBytes == CONN_BUF_LEN) {
        if (n > 0) {
            connBuf->bufUsed += n;
            return conn->nextCallback(conn);
        }
        if (n == 0) {
            FPRINTF_DEBUG("conn closed\n");
            goto closeConn;
        }
        // n < 0
        if (errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR) {
            return conn->nextCallback(conn);
        }
        goto error;
    }

    if (n > 0) {
        connBuf->bufUsed += n;
        connBuf->expectedBytes -= n;
        if (connBuf->expectedBytes > 0) {
            return;
        }
        return conn->nextCallback(conn);
    }

    if (n == 0) {
        FPRINTF_DEBUG("conn closed\n");
        goto closeConn;
    }

    // n < 0
    if (errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR) {
        return;
    }
error:
    FPRINTF("readN error: %s\n", strerror(errno));
closeConn:
    if (conn->assocConn) {
        closeConn(conn->assocConn);
    }
    closeConn(conn);
}

// before writeN, conn expect EPOLLIN
// if write done first try, call the nextCallback
// if not, modify conn expect to EPOLLOUT, callback to writeN
// when writeN complete, change back to EPOLLIN, call nextCallback
void writeN(struct conn *conn)
{
    struct connBuf *connBuf = conn->buf;

    FPRINTF_DEBUG("want write %d bytes\n", connBuf->expectedBytes);
    int n = write(conn->fd, connBuf->bufp, connBuf->expectedBytes);
    FPRINTF_DEBUG("write return %d\n", n);
    if (n > 0) {
        connBuf->bufp += n;
        connBuf->expectedBytes -= n;
        if (connBuf->expectedBytes == 0) {
            if (conn->expectedEvents & EPOLLOUT) {
                FPRINTF_DEBUG("write done, watch EPOLLIN\n");
                conn->expectedEvents = EPOLLIN;
                conn->callback       = NULL;
                struct epoll_event ev;
                ev.events   = EPOLLIN;
                ev.data.ptr = conn;
                if (epoll_ctl(epfd, EPOLL_CTL_MOD, conn->fd, &ev) == -1) {
                    FPRINTF("epoll_ctl mod error: %s\n", strerror(errno));
                    exit(1);
                }
            }
            return conn->nextCallback(conn);
        }
        goto epollout;
    }

    if (n == 0) {
        goto epollout;
    }

    // n < 0
    if (errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR) {
        goto epollout;
    }
    FPRINTF("writeN error: %s\n", strerror(errno));

    if (conn->assocConn) {
        closeConn(conn->assocConn);
    }
    closeConn(conn);
    return;

epollout:
    FPRINTF_DEBUG(HIGHLIGHT_START "write not complete, wait EPOLLOUT" HIGHLIGHT_END "\n");
    if (conn->expectedEvents & EPOLLOUT) {
        return;
    }

    conn->expectedEvents = EPOLLOUT;
    conn->callback       = writeN;

    struct epoll_event ev;
    ev.events   = EPOLLOUT;
    ev.data.ptr = conn;
    if (epoll_ctl(epfd, EPOLL_CTL_MOD, conn->fd, &ev) == -1) {
        FPRINTF("epoll_ctl mod error: %s\n", strerror(errno));
        exit(1);
    }
}

void delayCloseConn(struct conn *conn)
{
    FPRINTF_DEBUG("delay close conn\n");

    conn->callback     = readN;
    conn->nextCallback = NULL;
    resetConnBuf(conn->buf);
    conn->buf->expectedBytes = 0;
}

/*
    Request:
    +----+-----+-------+------+----------+----------+
    |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    +----+-----+-------+------+----------+----------+
    | 1  |  1  | X'00' |  1   | Variable |    2     |
    +----+-----+-------+------+----------+----------+
    Reply:
    +----+-----+-------+------+----------+----------+
    |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    +----+-----+-------+------+----------+----------+
    | 1  |  1  | X'00' |  1   | Variable |    2     |
    +----+-----+-------+------+----------+----------+
*/
void cmdReplyError(struct conn *conn, int8_t err)
{
    FPRINTF_DEBUG("cmd reply error: %d\n", err);

    conn->buf->buf[1] = err;
    conn->buf->expectedBytes = conn->buf->bufUsed;
    conn->buf->bufp = conn->buf->buf;
    conn->callback     = NULL;
    conn->nextCallback = delayCloseConn;
    writeN(conn);
}

void processCommandBind(struct conn *conn)
{
    cmdReplyError(conn, CMD_REPLY_NOT_SUPPORTED);
}

void processCommandUdpAssociate(struct conn *conn)
{
    cmdReplyError(conn, CMD_REPLY_NOT_SUPPORTED);
}

void proxyToRemoteTargetDone(struct conn *remoteConn);
void proxyToRemoteTarget(struct conn *clientConn);
void proxyToClientDone(struct conn *clientConn);
void proxyToClient(struct conn *remoteConn);

void proxyToRemoteTargetDone(struct conn *remoteConn)
{
    FPRINTF_DEBUG("client send data to remote done\n");

    // client
    remoteConn->assocConn->blocked    = 0;
    // remote
    remoteConn->callback     = readN;
    remoteConn->nextCallback = proxyToClient;
    resetConnBuf(remoteConn->buf);
    remoteConn->buf->expectedBytes = CONN_BUF_LEN;
}

void proxyToRemoteTarget(struct conn *clientConn)
{
    FPRINTF_DEBUG("client send data to remote, data length: ");

    if (clientConn->buf->bufUsed == 0) {
        FPRINTF_DEBUG("0\n");
        return;
    }

    FPRINTF_DEBUG("%d\n", clientConn->buf->bufUsed);

    clientConn->blocked = 1; // ignore clientConn events
    struct conn *remoteConn = clientConn->assocConn;
    remoteConn->buf->expectedBytes = remoteConn->buf->bufUsed;
    remoteConn->buf->bufp = remoteConn->buf->buf;
    remoteConn->callback     = NULL;
    remoteConn->nextCallback = proxyToRemoteTargetDone;
    writeN(remoteConn);
}

void proxyToClientDone(struct conn *clientConn)
{
    FPRINTF_DEBUG("remote send data to client done\n");

    // remote
    clientConn->assocConn->blocked    = 0;
    // client
    clientConn->callback     = readN;
    clientConn->nextCallback = proxyToRemoteTarget;
    resetConnBuf(clientConn->buf);
    clientConn->buf->expectedBytes = CONN_BUF_LEN;
}

void proxyToClient(struct conn *remoteConn)
{
    FPRINTF_DEBUG("remote send data to client, data length: ");

    if (remoteConn->buf->bufUsed == 0) {
        FPRINTF_DEBUG("0\n");
        return;
    }

    FPRINTF_DEBUG("%d\n", remoteConn->buf->bufUsed);

    remoteConn->blocked = 1; // ignore remoteConn events
    struct conn *clientConn = remoteConn->assocConn;
    clientConn->buf->expectedBytes = clientConn->buf->bufUsed;
    clientConn->buf->bufp = clientConn->buf->buf;
    clientConn->callback     = NULL;
    clientConn->nextCallback = proxyToClientDone;
    writeN(clientConn);
}

void startProxy(struct conn *clientConn)
{
    FPRINTF_DEBUG("start proxy\n");

    clientConn->callback     = readN;
    clientConn->nextCallback = proxyToRemoteTarget;
    resetConnBuf(clientConn->buf);
    clientConn->buf->expectedBytes = CONN_BUF_LEN;

    struct conn *remoteConn = clientConn->assocConn;
    remoteConn->expectedEvents = EPOLLIN;
    remoteConn->callback       = readN;
    remoteConn->nextCallback   = proxyToClient;

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.ptr = remoteConn;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, remoteConn->fd, &ev) == -1) {
        FPRINTF("epoll_ctl add error: %s\n", strerror(errno));
        exit(1);
    }
}

void confirmConnectedToRemoteTarget(struct conn *remoteConn)
{
    int optval = 0;
    socklen_t optlen = sizeof(optval);
    int ret = getsockopt(remoteConn->fd, SOL_SOCKET, SO_ERROR, &optval, &optlen);
    if (ret == -1) {
        FPRINTF("getsockopt error: %s\n", strerror(errno));
        goto error;
    }
    if (optval != 0) {
        FPRINTF("connect to remote target error: %s\n", strerror(errno));
        goto error;
    }
    // optval = 0, connect success
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);
    if (getsockname(remoteConn->fd, (struct sockaddr *)&addr, &addrlen) == -1) {
        FPRINTF("getsockname error: %s\n", strerror(errno));
        goto error;
    }
    optval = 1;
    if (setsockopt(remoteConn->fd, SOL_SOCKET, SO_KEEPALIVE, &optval, optlen) == -1) {
        FPRINTF("setsockopt keepalive error: %s\n", strerror(errno));
        goto error;
    }
    if (epoll_ctl(epfd, EPOLL_CTL_DEL, remoteConn->fd, NULL) == -1) {
        FPRINTF("epoll_ctl del fd error: %s\n", strerror(errno));
        exit(1);
    }

    FPRINTF_DEBUG(HIGHLIGHT_START "connected to remote target success" HIGHLIGHT_END "\n");
    FPRINTF_DEBUG("response client\n");

    struct conn *clientConn = remoteConn->assocConn;
    uint8_t *buf = clientConn->buf->buf;
    buf[1] = CMD_REPLY_SUCCESS;
    memcpy(buf + 4, &addr.sin_addr.s_addr, 4);
    memcpy(buf + 8, &addr.sin_port, 2);

    clientConn->buf->expectedBytes = 10; // 4 + 4 + 2
    clientConn->buf->bufp = clientConn->buf->buf;
    clientConn->callback     = NULL;
    clientConn->nextCallback = startProxy;
    writeN(clientConn);
    return;

error:
    closeConn(remoteConn);
    cmdReplyError(remoteConn->assocConn, CMD_REPLY_GENERRAL_SOCKS_ERROR);
}

void processCommandConnect(struct conn *conn)
{
#ifdef DEBUG
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, conn->buf->buf + 4, ip, INET_ADDRSTRLEN);
    uint16_t port = *((uint16_t *)(conn->buf->buf + 4 + 4));
    FPRINTF_DEBUG(HIGHLIGHT_START "try to connect %s:%d" HIGHLIGHT_END "\n", ip, ntohs(port));
#endif

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = *((uint16_t *)(conn->buf->buf + 4 + 4));
    addr.sin_addr.s_addr = *((uint32_t *)(conn->buf->buf + 4));

    int remotefd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (remotefd == -1) {
        FPRINTF("create remote socket error: %s\n", strerror(errno));
        cmdReplyError(conn, CMD_REPLY_GENERRAL_SOCKS_ERROR);
        return;
    }

    if (connect(remotefd, (struct sockaddr *)&addr, sizeof(addr)) != -1) {
        FPRINTF("!!!connect to remote target immediately!!!\n");
        exit(1);
    }

    if (errno != EINPROGRESS) {
        FPRINTF("connect error: %s\n", strerror(errno));
        cmdReplyError(conn, CMD_REPLY_GENERRAL_SOCKS_ERROR);
        return;
    }

    struct conn *remoteConn = getAFreeRemoteConn();
    remoteConn->fd             = remotefd;
    remoteConn->expectedEvents = EPOLLOUT;
    remoteConn->callback       = confirmConnectedToRemoteTarget;
    remoteConn->buf            = conn->buf;
#ifdef DEBUG
    inet_ntop(AF_INET, &addr.sin_addr, remoteConn->ip, INET_ADDRSTRLEN);
    remoteConn->port = ntohs(addr.sin_port);
#endif

    struct epoll_event ev;
    ev.events   = EPOLLOUT;
    ev.data.ptr = remoteConn;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, remotefd, &ev) == -1) {
        remoteConn->fd = -1;
        close(remotefd);
        FPRINTF("epoll_ctl add error: %s\n", strerror(errno));
        cmdReplyError(conn, CMD_REPLY_GENERRAL_SOCKS_ERROR);
        return;
    }

    remoteConn->assocConn = conn;
    conn->assocConn       = remoteConn;
}

void dispatchCommand(struct conn *conn)
{
    FPRINTF_DEBUG("dispatch command\n");

    if (conn->buf->expectedBytes == CONN_BUF_LEN) {
        // address type not supported
        cmdReplyError(conn, CMD_REPLY_ADDR_TYPE_NOT_SUPPORTED);
        return;
    }

    uint8_t *buf = (uint8_t *)conn->buf->buf;
    switch (buf[1]) {
    case CMD_CONNECT:
        return processCommandConnect(conn);
    case CMD_BIND:
        return processCommandBind(conn);
    case CMD_UDP_ASSOCIATE:
        return processCommandUdpAssociate(conn);
    }
}

void processCommandCalcLen(struct conn *conn)
{
    FPRINTF_DEBUG("got client command\n");

    uint8_t *buf = (uint8_t *)conn->buf->buf;
    if (buf[0] != SOCKS5_VER) {
        goto badFormat;
    }

    uint8_t cmd = buf[1];
    if (cmd != CMD_CONNECT && cmd != CMD_BIND && cmd != CMD_UDP_ASSOCIATE) {
        goto badFormat;
    }

    uint8_t addrType = buf[3];
    uint16_t dstAddrLen;
    if (addrType == ADDR_TYPE_IPV4) {
        dstAddrLen = 4 - 1;
    } else if (addrType == ADDR_TYPE_DOMAINNAME) {
        dstAddrLen = buf[4];
    } else if (addrType == ADDR_TYPE_IPV6) {
        dstAddrLen = 16 - 1;
    } else {
        dstAddrLen = CONN_BUF_LEN - 2;
    }

    FPRINTF_DEBUG("prepare to read command arguments\n");

    conn->buf->expectedBytes = dstAddrLen + 2;
    conn->nextCallback = dispatchCommand;
    return;

badFormat:
    FPRINTF("request format wrong\n");
    closeConn(conn);
}

void startProcessCommand(struct conn *conn)
{
    FPRINTF_DEBUG("wait for client command\n");

    conn->callback     = readN;
    conn->nextCallback = processCommandCalcLen;
    resetConnBuf(conn->buf);
    conn->buf->expectedBytes = 4 + 1;
}

/*
    +----+------+----------+------+----------+
    |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
    +----+------+----------+------+----------+
    | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
    +----+------+----------+------+----------+
*/
void doAuth(struct conn *conn)
{
    FPRINTF_DEBUG("got username/password, check it\n");

    uint8_t *buf = (uint8_t *)conn->buf->buf;
    uint8_t ulen = buf[1];
    uint8_t plen = buf[2 + ulen];
    void (*nextCallback)(struct conn *);

    if (ulen == usernameLen
        && plen == passwordLen
        && memcmp(buf + 2, username, ulen) == 0
        && memcmp(buf + 2 + ulen + 1, password, plen) == 0
    ) {
        buf[1] = AUTH_METHOD_USER_PASS_SUCCESS;
        nextCallback = startProcessCommand;
    } else {
        buf[1] = AUTH_METHOD_USER_PASS_FAILED;
        nextCallback = delayCloseConn;
        FPRINTF_DEBUG("auth failed\n");
    }

    FPRINTF_DEBUG(HIGHLIGHT_START "username/password OK" HIGHLIGHT_END "\n");
    FPRINTF_DEBUG("response client\n");

    conn->buf->expectedBytes = 2;
    conn->buf->bufp = buf;
    conn->callback     = NULL;
    conn->nextCallback = nextCallback;
    writeN(conn);
}

void authPasswordCalcLen(struct conn *conn)
{
    FPRINTF_DEBUG("prepare to read password\n");

    uint8_t *buf = (uint8_t *)conn->buf->buf;
    uint8_t plen = buf[2 + buf[1]];

    if (plen == 0) {
        FPRINTF("username/password request format wrong\n");
        closeConn(conn);
        return;
    }

    conn->buf->expectedBytes = plen;
    conn->nextCallback = doAuth;
}

void authUsernameCalcLen(struct conn *conn)
{
    FPRINTF_DEBUG("prepare to read username\n");

    uint8_t *buf = (uint8_t *)conn->buf->buf;

    if (buf[0] != AUTH_METHOD_USER_PASS_VER || buf[1] == 0) {
        FPRINTF("username/password request format wrong\n");
        closeConn(conn);
        return;
    }

    conn->buf->expectedBytes = buf[1] + 1;
    conn->nextCallback = authPasswordCalcLen;
}

void startAuth(struct conn *conn)
{
    FPRINTF_DEBUG("wait for client username/password message\n");

    conn->callback     = readN;
    conn->nextCallback = authUsernameCalcLen;
    resetConnBuf(conn->buf);
    conn->buf->expectedBytes = 2;
}

void selectAuthMethod(struct conn *conn)
{
    FPRINTF_DEBUG("got client auth methods\n");

    uint8_t *buf = (uint8_t *)conn->buf->buf;

    int i;
    uint8_t method = 0xFF;
    for (i = 0; i < buf[1]; i++) {
        if (buf[i + 2] == AUTH_METHOD_USER_PASS) {
            method = AUTH_METHOD_USER_PASS;
            break;
        }
    }

#ifdef DEBUG
    if (method == 0xFF) {
        FPRINTF_DEBUG("no acceptable methods\n");
    }
#endif

    FPRINTF_DEBUG("client support username/password authentication, good.\n");
    FPRINTF_DEBUG("response client\n");

    buf[1] = method;
    conn->buf->expectedBytes = 2;
    conn->buf->bufp = buf;
    conn->callback     = NULL;
    conn->nextCallback = method == 0xFF ? delayCloseConn : startAuth;
    writeN(conn);
}

/*
    +----+----------+----------+
    |VER | NMETHODS | METHODS  |
    +----+----------+----------+
    | 1  |    1     | 1 to 255 |
    +----+----------+----------+
*/
void selectAuthMethodCalcLen(struct conn *conn)
{
    FPRINTF_DEBUG("prepare to read auth methods\n");

    uint8_t *buf = (uint8_t *)conn->buf->buf;
    if (buf[0] != SOCKS5_VER || buf[1] == 0) {
        FPRINTF("version identifier/method selection message format wrong\n");
        closeConn(conn);
        return;
    }

    conn->buf->expectedBytes = buf[1];
    conn->nextCallback = selectAuthMethod;
}

void acceptClient(struct conn *listeningConn)
{
    FPRINTF_DEBUG(HIGHLIGHT_START "accept client" HIGHLIGHT_END "\n");

    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);

    int cfd = accept4(listeningConn->fd, &addr, &addrlen, SOCK_NONBLOCK);
    if (cfd == -1) {
        FPRINTF("accept4 error: %s", strerror(errno));
        return;
    }

    struct conn *conn = getAFreeClientConn();
    if (conn == NULL) {
        close(cfd);
        FPRINTF("too many conns, drop client\n");
        return;
    }

    int optval = 1;
    if (setsockopt(cfd, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval)) == -1) {
        close(cfd);
        FPRINTF("setsockopt keepalive error: %s\n", strerror(errno));
        return;
    }

#ifdef DEBUG
    inet_ntop(AF_INET, &addr.sin_addr, conn->ip, INET_ADDRSTRLEN);
    conn->port = ntohs(addr.sin_port);
    FPRINTF_DEBUG(HIGHLIGHT_START "accept %s:%d" HIGHLIGHT_END "\n", conn->ip, conn->port);
#endif

    conn->fd             = cfd;
    conn->expectedEvents = EPOLLIN;
    conn->callback       = readN;
    conn->nextCallback   = selectAuthMethodCalcLen;
    conn->assocConn      = NULL;
    resetConnBuf(conn->buf);
    conn->buf->expectedBytes = 2;

    struct epoll_event ev;
    ev.events   = EPOLLIN;
    ev.data.ptr = conn;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, cfd, &ev) == -1) {
        conn->fd = -1;
        close(cfd);
        FPRINTF("epoll_ctl add error: %s\n", strerror(errno));
    }
}

void start(int sfd)
{
    initConns();

    struct conn listeningConn;
    listeningConn.fd             = sfd;
    listeningConn.expectedEvents = EPOLLIN;
    listeningConn.callback       = acceptClient;
    listeningConn.blocked        = 0;

    struct epoll_event ev;
    ev.events   = EPOLLIN;
    ev.data.ptr = &listeningConn;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, sfd, &ev) == -1) {
        FPRINTF("epoll_ctl add error: %s\n", strerror(errno));
        exit(1);
    }

    struct epoll_event evList[1 + MAX_CONNS * 2];
    int ready;
    int i;
    struct conn *conn;
    while (1) {
        ready = epoll_wait(epfd, evList, MAX_CONNS * 2 + 1, 60000);
        if (ready == -1) {
            if (errno == EINTR) {
                continue;
            }
            FPRINTF("epoll_wait error: %s\n", strerror(errno));
            exit(1);
        }
        FPRINTF_DEBUG("epoll_wait return %d\n", ready);
        for (i = 0; i < ready; i++) {
            conn = (struct conn *)(evList[i].data.ptr);
#ifdef DEBUG
    if (conn->fd != sfd) {
        FPRINTF_DEBUG(HIGHLIGHT_START);
        if (conn->assocConn) {
            FPRINTF_DEBUG("%s:%d <--> %s:%d expects", conn->ip, conn->port, conn->assocConn->ip, conn->assocConn->port);
        } else {
            FPRINTF_DEBUG("%s:%d expects", conn->ip, conn->port);
        }
        if (conn->expectedEvents & EPOLLIN) {
            FPRINTF_DEBUG(" EPOLLIN");
        }
        if (conn->expectedEvents & EPOLLOUT) {
            FPRINTF_DEBUG(" EPOLLOUT");
        }
        FPRINTF_DEBUG(", now it got");
        if (evList[i].events & EPOLLIN) {
            FPRINTF_DEBUG(" EPOLLIN");
        }
        if (evList[i].events & EPOLLOUT) {
            FPRINTF_DEBUG(" EPOLLOUT");
        }
        FPRINTF_DEBUG(HIGHLIGHT_END "\n");
    }
#endif
            if (conn->expectedEvents & evList[i].events) {
                if (!conn->blocked) {
                    conn->callback(conn);
                }
            } else if (conn->fd == sfd) {
                FPRINTF("listening socket: unexpected events\n");
            } else {
                FPRINTF("unexpected events\n");
                if (conn->assocConn) {
                    closeConn(conn->assocConn);
                }
                closeConn(conn);
            }
        }
    }
}

int main(int argc, char **argv)
{
    char c;
    int port = 1080;
    int daemonize = 1;

    // options
    opterr = 0;
    while ((c = getopt(argc, argv, "u:p:P:Fh")) != -1) {
        switch (c) {
            case 'u':
                username = optarg;
                {
                    int len = strlen(username);
                    if (len > 200) {
                        printf("username too long\n");
                        exit(1);
                    }
                    usernameLen = len;
                }
                break;
            case 'p':
                password = optarg;
                {
                    int len = strlen(password);
                    if (len > 200) {
                        printf("password too long\n");
                        exit(1);
                    }
                    passwordLen = len;
                }
                break;
            case 'P':
                port = atoi(optarg);
                if (port <= 1024 || port > 65535) {
                    printf("port should > 1024 and <= 65535\n");
                    exit(1);
                }
                break;
            case 'F':
                daemonize = 0;
                break;
            default:
                help();
                exit(1);
        }
    }
    if (username == NULL || password == NULL) {
        help();
        exit(1);
    }
    // socket listening
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sfd == -1) {
        perror("socket");
        exit(1);
    }
    int optval = 1;
    if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) == -1) {
        perror("setsockopt");
        exit(1);
    }
    if (bind(sfd, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
        perror("bind");
        exit(1);
    }
    if (listen(sfd, 512) == -1) {
        perror("listen");
        exit(1);
    }
    // epoll
    epfd = epoll_create(1);
    if (epfd == -1) {
        perror("epoll_create");
        exit(1);
    }
    // signal
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);
    // daemon
    if (daemonize) {
        if ((logFile = fopen("my-socks5.log", "a")) == NULL) {
            perror("fopen");
            exit(1);
        }
        if (daemon(1, 0) == -1) {
            perror("daemon");
            exit(1);
        }
    } else {
        logFile = stdout;
    }
    // start
    FPRINTF("start, port = %d, pid = %d\n", port, getpid());
    FPRINTF("username: %s\n", username);
    FPRINTF("password: %s\n", password);
    start(sfd);

    return 0;
}
