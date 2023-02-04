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

#define MAX_CONNECTIONS     1024
#define BACKLOG             512
#define MAX_MESSAGE_LEN     1024
#define BUFFERS_COUNT       MAX_CONNECTIONS

void add_accept(struct io_uring *ring, int fd, struct sockaddr *client_addr, socklen_t *client_len, unsigned flags);
void add_socket_read(struct io_uring *ring, int fd, unsigned gid, size_t size, unsigned flags);
void add_socket_write(struct io_uring *ring, int fd, __u16 bid, size_t size, unsigned flags);
void add_provide_buf(struct io_uring *ring, __u16 bid, unsigned gid);

enum {
    ACCEPT,
    READ,
    WRITE,
    SENDFILE,
    PROV_BUF,
};

typedef struct conn_info {
    __u32 fd;
    __u16 type;
    __u16 bid;
} conn_info;

static char bufs[BUFFERS_COUNT][MAX_MESSAGE_LEN] = {0};
int group_id = 1337;

int get_socket(int portno)
{
    struct sockaddr_in serv_addr;

    // setup socket
    int sock_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    const int val = 1;
    setsockopt(sock_listen_fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));

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

int main(int argc, char *argv[])
{

    //webroot_check_exists(CONFIG.web_root);
    //http_connection_pool_init();
    //file_cache_init();
    //connection_timeout_init();




    // NETWORK only
    // some variables we need
    int portno = 8090;//strtol(argv[1], NULL, 10);
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int sock_listen_fd = get_socket(portno);





    // IO after this
    // initialize io_uring
    struct io_uring_params params;
    struct io_uring ring;
    memset(&params, 0, sizeof(params));
    //params.flags |= IORING_SETUP_SQPOLL;


    if (io_uring_queue_init_params(MAX_MESSAGE_LEN, &ring, &params) < 0) {
        perror("io_uring_init_failed...\n");
        exit(1);
    }

    // check if IORING_FEAT_FAST_POLL is supported
    if (!(params.features & IORING_FEAT_FAST_POLL)) {
        printf("IORING_FEAT_FAST_POLL not available in the kernel, quiting...\n");
        exit(0);
    }

    // check if buffer selection is supported
    struct io_uring_probe *probe;
    probe = io_uring_get_probe_ring(&ring);
    if (!probe || !io_uring_opcode_supported(probe, IORING_OP_PROVIDE_BUFFERS)) {
        printf("Buffer select not supported, skipping...\n");
        exit(0);
    }
    free(probe);



    puts ("checked stats, now make rings");


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
        // io_uring_submit_and_wait is not needed if SQ_POLL is used

        io_uring_submit_and_wait(&ring, 1);
        struct io_uring_cqe *cqe;
        unsigned head;
        unsigned count = 0;

        // go through all CQEs
        io_uring_for_each_cqe(&ring, head, cqe) {
            ++count;
            struct conn_info conn_i;
            memcpy(&conn_i, &cqe->user_data, sizeof(conn_i));

            int type = conn_i.type;
            if (cqe->res == -ENOBUFS) {
                fprintf(stdout, "bufs in automatic buffer selection empty, this should not happen...\n");
                fflush(stdout);
                exit(1);
            } else if (type == PROV_BUF) {
                if (cqe->res < 0) {
                    printf("cqe->res = %d\n", cqe->res);
                    exit(1);
                }
            } else if (type == ACCEPT) {
                int sock_conn_fd = cqe->res;
                // only read when there is no error, >= 0
                if (sock_conn_fd >= 0)
                    add_socket_read(&ring, sock_conn_fd, group_id, MAX_MESSAGE_LEN, IOSQE_BUFFER_SELECT);

                // new connected client; read data from socket and re-add accept to monitor for new connections
                add_accept(&ring, sock_listen_fd, (struct sockaddr *)&client_addr, &client_len, 0);
            } else if (type == READ) {
                int bytes_read = cqe->res;
                int bid = cqe->flags >> 16;
                if (cqe->res <= 0) {
                    // read failed, re-add the buffer
                    add_provide_buf(&ring, bid, group_id);
                    // connection closed or error
                    close(conn_i.fd);
                } else {
                    // bytes have been read into bufs, now add write to socket sqe
                    add_socket_write(&ring, conn_i.fd, bid, bytes_read, 0);
                }
            } else if (type == WRITE) {
                // write has been completed, first re-add the buffer
                add_provide_buf(&ring, conn_i.bid, group_id);
                // add a new read for the existing connection
                add_socket_read(&ring, conn_i.fd, group_id, MAX_MESSAGE_LEN, IOSQE_BUFFER_SELECT);
            }
        }

        io_uring_cq_advance(&ring, count);
    }

    return 0;
}

void add_accept(struct io_uring *ring, int fd, struct sockaddr *client_addr, socklen_t *client_len, unsigned flags) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    io_uring_prep_accept(sqe, fd, client_addr, client_len, 0);
    io_uring_sqe_set_flags(sqe, flags);

    conn_info conn_i = {
        .fd = fd,
        .type = ACCEPT,
    };

    sqe->user_data = *((uint64_t*)&conn_i);
    //memcpy(&sqe->user_data, &conn_i, sizeof(conn_i));
}

/*
void add_sendfile(struct io_uring *ring, int fd_file, int64_t off_file, int fd_socket, int64_t off_socket, int bytes) {

    io_uring_push_send((struct io_uring *)conn->svr->ring, conn->fd,
                       fresstr->buf, fresstr->len, (void *)conn,
                       MSG_MORE, IOSQE_IO_LINK);

    io_uring_push_splice((struct io_uring *)conn->svr->ring,
                         res.file_fd, 0, conn->svr->pipefds[1], -1,
                         res.file_sz, (void *)conn, IOSQE_IO_LINK);

    io_uring_push_splice((struct io_uring *)conn->svr->ring,
                         conn->svr->pipefds[0], -1, conn->fd, -1,
                         res.file_sz, (void *)conn, 0);



    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    io_uring_prep_splice(sqe, fd_file, off_file, fd_socket, off_socket, bytes, // num bytes for file to send
                        unsigned int splice_flags);

    io_uring_sqe_set_flags(sqe, flags);
    conn_info conn_i = {
        .fd = fd,
        .type = SENDFILE,
    };

    sqe->user_data = *((uint64_t*)&conn_i);
}
*/

void add_socket_read(struct io_uring *ring, int fd, unsigned gid, size_t message_size, unsigned flags) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    io_uring_prep_recv(sqe, fd, NULL, message_size, 0);
    io_uring_sqe_set_flags(sqe, flags);
    sqe->buf_group = gid;

    conn_info conn_i = {
        .fd = fd,
        .type = READ,
    };

    sqe->user_data = *((uint64_t*)&conn_i);
    //memcpy(&sqe->user_data, &conn_i, sizeof(conn_i));
}

void add_socket_write(struct io_uring *ring, int fd, __u16 bid, size_t message_size, unsigned flags) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    io_uring_prep_send(sqe, fd, &bufs[bid], message_size, 0);
    io_uring_sqe_set_flags(sqe, flags);

    conn_info conn_i = {
        .fd = fd,
        .type = WRITE,
        .bid = bid,
    };

    sqe->user_data = *((uint64_t*)&conn_i);
    //memcpy(&sqe->user_data, &conn_i, sizeof(conn_i));
}

void add_provide_buf(struct io_uring *ring, __u16 bid, unsigned gid) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    io_uring_prep_provide_buffers(sqe, bufs[bid], MAX_MESSAGE_LEN, 1, gid, bid);

    conn_info conn_i = {
        .fd = 0,
        .type = PROV_BUF,
    };

    sqe->user_data = *((uint64_t*)&conn_i);
    //memcpy(&sqe->user_data, &conn_i, sizeof(conn_i));
}
