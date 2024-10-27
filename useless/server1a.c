#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <liburing.h>
////#include "http.h"

#define MAX_CONNECTIONS     8192
#define BACKLOG             2048
#define MAX_MESSAGE_LEN     2048
#define BUFFERS_COUNT       MAX_CONNECTIONS

#define str8le(a, b, c, d, e, f, g, h) \
(a|(u16(b)<<8)|(u32(c)<<16)|(u32(d)<<24)|(u64(e)<<32)|(u64(f)<<40)|(u64(g)<<48)|(u64(h)<<56))

#define str8be(a, b, c, d, e, f, g, h) \
(h|(u16(g)<<8)|(u32(f)<<16)|(u32(e)<<24)|(u64(d)<<32)|(u64(c)<<40)|(u64(b)<<48)|(u64(a)<<56))


#define str7le(a, b, c, d, e, f, g) \
(a|(u16(b)<<8)|(u32(c)<<16)|(u32(d)<<24)|(u64(e)<<32)|(u64(f)<<40)|(u64(g)<<48))

#define str7be(a, b, c, d, e, f, g) \
(g|(u16(f)<<8)|(u32(e)<<16)|(u32(d)<<24)|(u64(c)<<32)|(u64(b)<<40)|(u64(a)<<48))


#define str6le(a, b, c, d, e, f) \
(a|(u16(b)<<8)|(u32(c)<<16)|(u32(d)<<24)|(u64(e)<<32)|(u64(f)<<40))

#define str6be(a, b, c, d, e, f) \
(f|(u16(e)<<8)|(u32(d)<<16)|(u32(c)<<24)|(u64(b)<<32)|(u64(a)<<40))


#define str5le(a, b, c, d, e) \
(a|(u16(b)<<8)|(u32(c)<<16)|(u32(d)<<24)|(u64(e)<<32))

#define str5be(a, b, c, d, e) \
(e|(u16(d)<<8)|(u32(c)<<16)|(u32(b)<<24)|(u64(a)<<32))


#define str4le(a, b, c, d) \
(a|(u16(b)<<8)|(u32(c)<<16)|(u32(d)<<24))

#define str4be(a, b, c, d) \
(d|(u16(c)<<8)|(u32(b)<<16)|(u32(a)<<24))


#define str3le(a, b, c) \
(a|(u16(b)<<8)|(u32(c)<<16))

#define str3be(a, b, c) \
(c|(u16(b)<<8)|(u32(a)<<16))


#define str2le(a, b) \
(a|(u16(b)<<8))

#define str2be(a, b) \
(b|(u16(a)<<8))

#define substr4_le(x) \
(x & 0xFFFFFFFFUL)
#define substr4_be(x) \
(x >> 4)

#define substr5_le(x) \
(x & 0xFFFFFFFFFFUL)
#define substr5_be(x) \
(x >> 3)

#define substr6_le(x) \
(x & 0xFFFFFFFFFFFFUL)
#define substr6_be(x) \
(x >> 2)

#define substr7_le(x) \
(x & 0xFFFFFFFFFFFFFFUL)
#define substr7_be(x) \
(x >> 1)





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
  int fd;
  __u16 type;
  __u16 bid;
} conn_info;

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)

static struct io_uring ring;

static uint8_t recvbuf[10000];
static char bufs[BUFFERS_COUNT][MAX_MESSAGE_LEN] = {0};
int group_id = 1337;

/*
static bool cont = true;

static void sigint_handle(int no)
{
  (void)no;
  cont = false;
}*/

int get_socket(int portno)
{
  struct sockaddr_in serv_addr;

  // setup socket
  int sock_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
  const int val = 1;

  if (setsockopt(sock_listen_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT | SO_ZEROCOPY, &val, sizeof(val)))
    perror("setsockopt");

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
  int portno = 8888;
  //https://stackoverflow.com/questions/42906209/how-to-get-client-ip-by-the-socket-number-in-c
  struct sockaddr_in client_addr;
  socklen_t client_len = sizeof(client_addr);
  int sock_listen_fd = get_socket(portno);


  struct __kernel_timespec *tsPtr, ts;
  memset(&ts, 0, sizeof(ts));
  tsPtr = &ts;
  ts.tv_nsec = 100;


  setup_params(&ring);

  struct io_uring_probe *probe;
  probe = io_uring_get_probe_ring(&ring);
  if (!probe || !io_uring_opcode_supported(probe, IORING_OP_PROVIDE_BUFFERS)) {
    printf("Buffer select not supported, skipping...\n");
    exit(0);
  }

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

  int res = -1;

  // start event loop
  while (1) {

    do { res = io_uring_submit_and_wait_timeout(&ring, &cqe, 1, tsPtr, NULL); } while (res < 0);

    //io_uring_submit_and_wait(&ring, 1);
    unsigned head;
    unsigned count = 0;

    // go through all CQEs
    io_uring_for_each_cqe(&ring, head, cqe) {
      ++count;
      struct conn_info conn_i;
      memcpy(&conn_i, &cqe->user_data, sizeof(conn_i));

      int type = conn_i.type;
      if (likely(cqe->res != -ENOBUFS)) {
        if (type == PROV_BUF) {
          if (unlikely(cqe->res < 0)) {
            printf("cqe->res = %d\n", cqe->res);
            exit(1);
          }
        } else if (type == READ) {
          int bytes_read = cqe->res;
          int bid = cqe->flags >> 16;
          if (unlikely(cqe->res <= 0)) {
            puts("failed buffer read");

            // read failed, re-add the buffer
            add_provide_buf(&ring, bid, group_id);
            // connection closed or error
            close(conn_i.fd);
          } else {
            printf("%d\n",bytes_read);
            write(2,(char*)recvbuf, bytes_read);
            //recvbuf[bytes_read]=0;

            // parse here, to decide if socket or sendfile
            ////struct http_request req;
            ////struct phr_http_header hdrs[64];
            add_socket_write(&ring, conn_i.fd, bid, bytes_read, 0);
          }
        } else if (type == WRITE) {
          // write has been completed, first re-add the buffer
          add_provide_buf(&ring, conn_i.bid, group_id);
          // add a new read for the existing connection
          add_socket_read(&ring, conn_i.fd, group_id, MAX_MESSAGE_LEN, IOSQE_BUFFER_SELECT);
        } else if (type == ACCEPT) {
          int sock_conn_fd = cqe->res;

          // only read the future data when there is no error, >= 0
          if (sock_conn_fd >= 0)
            add_socket_read(&ring, sock_conn_fd, group_id, MAX_MESSAGE_LEN, IOSQE_BUFFER_SELECT);

          // new connected client; read data from socket and re-add accept to monitor for new connections
          // ALSO ACCEPT NEW CONNECTIONS FROM MORE CLIENTS
          add_accept(&ring, sock_listen_fd, (struct sockaddr *)&client_addr, &client_len, 0);
        } else if (type == SENDFILE) {
          puts("lol sendfile");
        } else {
          puts("something else");
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

void add_accept(struct io_uring *ring, int fd, struct sockaddr *client_addr, socklen_t *client_len, unsigned flags)
{
  struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
  io_uring_prep_accept(sqe, fd, client_addr, client_len, 0);
  io_uring_sqe_set_flags(sqe, flags);

  conn_info conn_i = {
    .fd = fd,
    .type = ACCEPT,
  };

  memcpy(&sqe->user_data, &conn_i, sizeof(conn_i));
}



void add_socket_read(struct io_uring *ring, int fd, unsigned gid, size_t message_size, unsigned flags)
{
  struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
  io_uring_prep_recv(sqe, fd, recvbuf, message_size, 0);
  io_uring_sqe_set_flags(sqe, flags);
  sqe->buf_group = gid;

  conn_info conn_i = {
    .fd = fd,
    .type = READ,
  };

  recvbuf[message_size]=0;

  memcpy(&sqe->user_data, &conn_i, sizeof(conn_i));
}

// idx because IOSQE_FIXED_FILE means the recv will take idx as an argument
// instead of the literal file descriptor
static int add_recv(struct ctx *ctx, int idx)
{
  struct io_uring_sqe *sqe;

  if (get_sqe(ctx, &sqe))
    return -1;

  io_uring_prep_recv_multishot(sqe, idx, &ctx->msg, MSG_TRUNC);
  //always had IOSQE_BUFFER_SELECT in the standard read
  // fixed file not present though
  sqe->flags |= IOSQE_FIXED_FILE;
  sqe->flags |= IOSQE_BUFFER_SELECT;
  sqe->buf_group = 0;
  io_uring_sqe_set_data64(sqe, BUFFERS + 1);
  return 0;
}

static void recycle_buffer(struct ctx *ctx, int idx)
{
  io_uring_buf_ring_add(ctx->buf_ring, get_buffer(ctx, idx), buffer_size(ctx), idx, io_uring_buf_ring_mask(BUFFERS), 0);
  io_uring_buf_ring_advance(ctx->buf_ring, 1);
}






const char* sz = "HTTP/1.1 200 OK\r\nServer: IOU69420\r\nConnection: keep-alive\r\nContent-Length: 10\r\nContent-Type: text/plain\r\n\r\nHello Baby";

void add_socket_write(struct io_uring *ring, int fd, __u16 bid, size_t message_size, unsigned flags)
{
  struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
  //puts(bufs[bid]);
  //io_uring_prep_send(sqe, fd, &bufs[bid], message_size, 0);
  write(2,(char*)bufs[bid],message_size);
  puts("");

  io_uring_prep_send(sqe, fd, sz, strlen(sz), MSG_ZEROCOPY);
  io_uring_sqe_set_flags(sqe, flags);

  conn_info conn_i = {
    .fd = fd,
    .type = WRITE,
    .bid = bid,
  };

  //io_uring_submit_and_wait_timeout();
  memcpy(&sqe->user_data, &conn_i, sizeof(conn_i));
}

void add_provide_buf(struct io_uring *ring, __u16 bid, unsigned gid)
{
  struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
  io_uring_prep_provide_buffers(sqe, bufs[bid], MAX_MESSAGE_LEN, 1, gid, bid);

  conn_info conn_i = {
    .fd = 0,
    .type = PROV_BUF,
  };

  memcpy(&sqe->user_data, &conn_i, sizeof(conn_i));
}


/*
int io_uring_register_buf_ring(struct io_uring *ring,
             struct io_uring_buf_reg *reg,
             unsigned int __maybe_unused flags)

             */
