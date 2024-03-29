#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <liburing.h>
////#include "http.h"

#define MAX_CONNECTIONS     1024
#define BACKLOG             512
#define MAX_MESSAGE_LEN     4096
#define BUFFERS_COUNT       MAX_CONNECTIONS

void add_accept(struct io_uring *ring, int fd, struct sockaddr *client_addr, socklen_t *client_len, unsigned flags);
void add_socket_read(struct io_uring *ring, int fd, unsigned gid, size_t size, unsigned flags);
void add_socket_write(struct io_uring *ring, int fd, __u16 bid, size_t size, unsigned flags);
void add_provide_buf(struct io_uring *ring, __u16 bid, unsigned gid);

enum {
    ACCEPT,
    RECV,
    SEND,
    SENDFILE,
    PROV_BUF,
    CLOSE
};
/*
typedef struct conn_info {
    __u32 fd;
    __u16 type;
    __u16 bid;
} conn_info;*/

#define CREATE_CQE_INFO(fd, bid, type) (((uint64_t)fd << 32) | ((uint64_t)bid << 16) | type)
#define EXTRACT_FD(cqe_data) (cqe_data >> 32)
#define EXTRACT_BID(cqe_data) ((cqe_data >> 16) & 0xFFFF)
#define EXTRACT_TYPE(cqe_data) (cqe_data & 0xFFFF)

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)
static struct io_uring ring;

static uint8_t recvbuf[10000];
static char bufs[BUFFERS_COUNT][MAX_MESSAGE_LEN] = {0};
int group_id = 1337;


int get_socket(int portno)
{
    struct sockaddr_in serv_addr;

    // setup socket
    int sock_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    const int val = 1;
    setsockopt(sock_listen_fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));

    if (setsockopt(sock_listen_fd, SOL_SOCKET, SO_ZEROCOPY, &val, sizeof(val)))
        perror("setsockopt zerocopy");

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(portno);
    serv_addr.sin_addr.s_addr = INADDR_ANY;

    // bind and listen
    if (bind(sock_listen_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Error binding socket...\n");
        exit(1);
    }

    if (listen(sock_listen_fd, BACKLOG) < 0) {
        perror("Error listening on socket...\n");
        exit(1);
    }

    printf("io_uring echo server listening for connections on port: %d\n", portno);

    return sock_listen_fd;
}

void setup_params(struct io_uring* ring)
{
    struct io_uring_params params;
    memset(&params, 0, sizeof(params));
    params.flags |= IORING_SETUP_DEFER_TASKRUN;
    params.flags |= IORING_SETUP_SINGLE_ISSUER;

    if (io_uring_queue_init_params(MAX_MESSAGE_LEN, ring, &params) < 0) {
        perror("io_uring_init_failed...\n");
        exit(1);
    }

    // check if IORING_FEAT_FAST_POLL is supported
    if (!(params.features & IORING_FEAT_FAST_POLL)) {
        printf("IORING_FEAT_FAST_POLL not available in the kernel, quiting...\n");
        exit(0);
    }
}

int main(int argc, char *argv[])
{
    // NETWORK only
    // some variables we need
    int portno = 9999;//strtol(argv[1], NULL, 10);
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int sock_listen_fd = get_socket(portno);

    //struct __kernel_timespec *tsPtr, ts;
    //memset(&ts, 0, sizeof(ts));
    //tsPtr = &ts;

    // IO after this
    // initialize io_uring
    setup_params(&ring);

    // check if buffer selection is supported
    struct io_uring_probe *probe;
    probe = io_uring_get_probe_ring(&ring);
    if (!probe || !io_uring_opcode_supported(probe, IORING_OP_PROVIDE_BUFFERS)) {
        printf("Buffer select not supported, skipping...\n");
        exit(0);
    }

    puts ("checked stats, now make rings");
    //int res = 0;

    // register buffers for buffer selection
    struct io_uring_sqe *sqe;
    struct io_uring_cqe *cqe;

    sqe = io_uring_get_sqe(&ring);
    if (!sqe) {
        puts("sqe is null");
        return 0;
    }
    io_uring_prep_provide_buffers(sqe, bufs, MAX_MESSAGE_LEN, BUFFERS_COUNT, group_id, 0);

    puts("uring buffers provided");

    io_uring_submit(&ring);
    io_uring_wait_cqe(&ring, &cqe);
    if (cqe->res < 0) {
        printf("cqe->res = %d\n", cqe->res);
        exit(1);
    }
    io_uring_cqe_seen(&ring, cqe);

    puts("setup uring fully, now add accept");


    // add first accept SQE to monitor for new incoming connections
    add_accept(&ring, sock_listen_fd, (struct sockaddr *)&client_addr, &client_len, 0);

    // start event loop
    while (1) {
        // io uring enter
        io_uring_submit_and_wait(&ring, 1);
        unsigned head;
        unsigned count = 0;

        // go through all CQEs
        io_uring_for_each_cqe(&ring, head, cqe) {
            ++count;
            //struct conn_info conn_i;
            //memcpy(&conn_i, &cqe->user_data, sizeof(conn_i));
            uint64_t cqe_data = cqe->user_data;

            uint64_t cfd = EXTRACT_FD(cqe_data);
            uint64_t ctype = EXTRACT_TYPE(cqe_data);

            if (cqe->res != -ENOBUFS) {
                if (ctype == PROV_BUF) {
                    if (unlikely(cqe->res < 0)) {
                        printf("cqe->res = %d\n", cqe->res);
                        exit(1);
                    }
                } else if (ctype == RECV) {
                    int bytes_read = cqe->res;
                    int bid = cqe->flags >> 16;
                    if (cqe->res <= 0) {
                        //puts("failed");

                        // read failed, re-add the buffer
                        add_provide_buf(&ring, bid, group_id);
                        // connection closed or error
                        // SHOULD WE DO SPECIAL ONE
                        close(cfd);
                    } else {
                        //printf("%d\n",bytes_read);
                        //recvbuf[bytes_read]=0;

                        // parse here, to decide if socket or sendfile
                        ////struct http_request req;
                        ////struct phr_http_header hdrs[64];

                        if (true) {
                            // bytes have been read into bufs, now add write to socket sqe
                            add_socket_write(&ring, cfd, bid, bytes_read, 0);
                        } else {
                            // possibly [if there is a file requested]
                            ////add_socket_sendfile(&ring,);
                        }
                    }
                } else if (ctype == SEND) {
                    // write has been completed, first re-add the buffer
                    add_provide_buf(&ring, EXTRACT_BID(cqe_data), group_id);
                    // add a new read for the existing connection
                    add_socket_read(&ring, cfd, group_id, MAX_MESSAGE_LEN, IOSQE_BUFFER_SELECT);
                } else if (ctype == ACCEPT) {
                    int sock_conn_fd = cqe->res;

                    // only read the future data when there is no error, >= 0
                    if (sock_conn_fd >= 0)
                        add_socket_read(&ring, sock_conn_fd, group_id, MAX_MESSAGE_LEN, IOSQE_BUFFER_SELECT);

                    // new connected client; read data from socket and re-add accept to monitor for new connections
                    // ALSO ACCEPT NEW CONNECTIONS FROM MORE CLIENTS
                    add_accept(&ring, sock_listen_fd, (struct sockaddr *)&client_addr, &client_len, 0);
                } else if (ctype == SENDFILE) {
                    puts("lol sendfile");
                }
            } else {
                fprintf(stdout, "bufs in automatic buffer selection empty, this should not happen...\n");
                fflush(stdout);
                exit(1);
            }
        }

        io_uring_cq_advance(&ring, count);
    }

    return 0;
}
/*
void add_sendfile(struct io_uring *ring, int fd_file, int64_t off_file, int fd_socket, int64_t off_socket, int bytes)
{
    //https://man7.org/linux/man-pages/man3/io_uring_prep_recv.3.html

    io_uring_prep_splice(sqe,
                         fd_file,
                         off_file,
                         fd_socket,
                         off_socket?,
                         bytes_for_socket,
                         unsigned int splice_flags);


    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    io_uring_prep_splice(sqe, fd_file, off_file, fd_socket, off_socket, bytes, // num bytes for file to send
                         0); // unsigned int splice_flags);

    io_uring_sqe_set_flags(sqe, flags);
    conn_info conn_i = {
        .fd = fd,
        .type = SENDFILE,
    };

    sqe->user_data = *((uint64_t*)&conn_i);
    memcpy(&sqe->user_data, &conn_i, sizeof(conn_i));
}
*/

void handle_recv(struct io_uring_cqe* cqe)
{
    /*

    */

}

void add_accept(struct io_uring *ring, int fd, struct sockaddr *client_addr, socklen_t *client_len, unsigned flags)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    io_uring_prep_accept(sqe, fd, client_addr, client_len, 0);
    io_uring_sqe_set_flags(sqe, flags);

    sqe->user_data = CREATE_CQE_INFO(fd, 0, ACCEPT);
}

void add_socket_read(struct io_uring *ring, int fd, unsigned gid, size_t message_size, unsigned flags)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    io_uring_prep_recv(sqe, fd, recvbuf, message_size, 0);
    io_uring_sqe_set_flags(sqe, flags);
    sqe->buf_group = gid;

    recvbuf[message_size] = 0;

    sqe->user_data = CREATE_CQE_INFO(fd, 0, RECV);
}

const char* sz = "HTTP/1.1 200 OK\r\nServer: IOU69420\r\nConnection: keep-alive\r\nContent-Length: 10\r\n\r\nHello Baby";

void add_socket_write(struct io_uring *ring, int fd, __u16 bid, size_t message_size, unsigned flags)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    //puts(bufs[bid]);
    //io_uring_prep_send(sqe, fd, &bufs[bid], message_size, 0);

    io_uring_prep_send(sqe, fd, sz, strlen(sz), MSG_ZEROCOPY);
    io_uring_sqe_set_flags(sqe, flags);

    sqe->user_data = CREATE_CQE_INFO(fd, bid, SEND);
}

void add_provide_buf(struct io_uring *ring, __u16 bid, unsigned gid)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    io_uring_prep_provide_buffers(sqe, bufs[bid], MAX_MESSAGE_LEN, 1, gid, bid);

    sqe->user_data = CREATE_CQE_INFO(0, 0, PROV_BUF);
}


void add_socket_close(struct io_uring *ring, int fd)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    io_uring_prep_close(sqe, fd);

    sqe->user_data = CREATE_CQE_INFO(fd, 0, CLOSE);
}

