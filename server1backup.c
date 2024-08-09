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


#define QD 64
#define BUF_SHIFT 12 /* 4k */
#define CQES (QD * 16)
#define BUFFERS CQES // 1024
#define CONTROLLEN 0



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


struct sendmsg_ctx {
  struct msghdr msg;
  struct iovec iov;
};

struct ctx {
  struct io_uring ring;
  struct io_uring_buf_ring *buf_ring;
  unsigned char *buffer_base;
  struct msghdr msg;
  int buf_shift;
  int af;
  bool verbose;
  struct sendmsg_ctx send[BUFFERS];
  size_t buf_ring_size;
};



static int setup_sock(int af, int port)
{
  int ret;
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    perror("socket");
    return -1;
  }

  struct sockaddr_in addr = {
    .sin_family = af,
    .sin_port = htons(port),
    .sin_addr = { INADDR_ANY }
  };

  if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
    perror("bind");
    close(fd);
    return -1;
  }

  return fd;
}


int get_socket(int portno)
{
  struct sockaddr_in serv_addr;
  int sock_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
  const int val = 1;

  if (setsockopt(sock_listen_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT | SO_ZEROCOPY, &val, sizeof(val))) {
    perror("setsockopt");
    exit(1);
  }
  
  /*
  memset(&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(portno);
  serv_addr.sin_addr.s_addr = INADDR_ANY;
  */
  struct sockaddr_in addr = {
    .sin_family = af,
    .sin_port = htons(port),
    .sin_addr = { INADDR_ANY }
  };

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





static size_t buffer_size(struct ctx *ctx)
{
  return 1U << ctx->buf_shift;
}

static uint8_t* get_buffer(struct ctx *ctx, int idx)
{
  return ctx->buffer_base + (idx << ctx->buf_shift);
}

/*
  build a io_uring_buf_reg and then register the ring buffer
*/
static int setup_buffer_pool(struct ctx *ctx)
{
  int ret, i;
  void *mapped;


  //The size of the ring is the product of ring_entries and the size of struct io_uring_buf
  ctx->buf_ring_size = (sizeof(struct io_uring_buf) + buffer_size(ctx)) * BUFFERS;

  mapped = mmap(NULL, ctx->buf_ring_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
  if (mapped == MAP_FAILED) {
    fprintf(stderr, "buf_ring mmap: %s\n", strerror(errno));
    return -1;
  }
  // buf_ring is the beginning 
  ctx->buf_ring = (struct io_uring_buf_ring *)mapped;


  io_uring_buf_ring_init(ctx->buf_ring);

  /*
  The ring_addr field must contain the address to the memory
  allocated to fit this ring.  The memory must be page aligned and
  hence allocated appropriately using eg posix_memalign(3) or
  similar. 

  ring_entries is the desired
  size of the ring, and must be a power-of-2 in size. The maximum
  size allowed is 2^15 (32768). 
  */
  // the BGID here is needed to identify the recvs and sends...
  struct io_uring_buf_reg reg = {
    .ring_addr = (uint64_t)ctx->buf_ring,
    .ring_entries = BUFFERS,
    .bgid = 0
  };

  // buffer_base is 
  ctx->buffer_base = (uint8_t *)ctx->buf_ring + sizeof(struct io_uring_buf) * BUFFERS;

  // flags must be 0
  ret = io_uring_register_buf_ring(&ctx->ring, &reg, 0);
  if (ret) {
    fprintf(stderr, "buf_ring init failed: %s\n" "NB This requires a kernel version >= 6.0\n", strerror(-ret));
    return ret;
  }

  // add each individual buffer at each memory address
  /*
     void io_uring_buf_ring_add(struct io_uring_buf_ring *br,
                                void *addr,
                                unsigned int len,
                                unsigned short bid,
                                int mask,
                                int buf_offset);

     adds a new buffer to the shared buffer ring br.
     The buffer address is indicated by addr and is
     of len bytes of length.  *bid is the buffer ID, which will be
     returned in the CQE*.  mask is the size mask of the ring,
     available from io_uring_buf_ring_mask(3).  buf_offset is the
     offset to insert at from the current tail

     If just one buffer is
     provided before the ring tail is committed with
     io_uring_buf_ring_advance(3) or io_uring_buf_ring_cq_advance(3),
     then buf_offset should be 0. If buffers are provided in a loop
     before being committed, the buf_offset must be incremented by one
     for each buffer added.

  */
  for (i = 0; i < BUFFERS; i++)
    io_uring_buf_ring_add(ctx->buf_ring, get_buffer(ctx, i), buffer_size(ctx), i, io_uring_buf_ring_mask(BUFFERS), i);

  // advance buffer
  io_uring_buf_ring_advance(ctx->buf_ring, BUFFERS);

  return 0;
}





static int setup_context(struct ctx *ctx)
{
  struct io_uring_params params;
  int ret;

  memset(&params, 0, sizeof(params));
  params.cq_entries = QD * 8;
  params.flags = (IORING_SETUP_SUBMIT_ALL | IORING_SETUP_COOP_TASKRUN | IORING_SETUP_CQSIZE);
  params.flags = (IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_SINGLE_ISSUER);

  ret = io_uring_queue_init_params(QD, &ctx->ring, &params);
  if (ret < 0) {
    fprintf(stderr, "queue_init failed: %s\n" "NB: This requires a kernel version >= 6.0\n", strerror(-ret));
    return ret;
  }

  ret = setup_buffer_pool(ctx);
  if (ret)
    io_uring_queue_exit(&ctx->ring);


  // check if IORING_FEAT_FAST_POLL is supported
  if (!(params.features & IORING_FEAT_FAST_POLL)) {
    printf("IORING_FEAT_FAST_POLL not available in the kernel, quiting...\n");
    exit(0);
  }

  memset(&ctx->msg, 0, sizeof(ctx->msg));
  ctx->msg.msg_namelen = sizeof(struct sockaddr_storage);
  ctx->msg.msg_controllen = CONTROLLEN;

  return ret;
}




static void cleanup_context(struct ctx *ctx)
{
  munmap(ctx->buf_ring, ctx->buf_ring_size);
  io_uring_queue_exit(&ctx->ring);
}



static bool get_sqe(struct ctx *ctx, struct io_uring_sqe **sqe)
{
  *sqe = io_uring_get_sqe(&ctx->ring);

  if (!*sqe) {
    io_uring_submit(&ctx->ring);
    *sqe = io_uring_get_sqe(&ctx->ring);
  }
  
  if (!*sqe) {
    fprintf(stderr, "cannot get sqe\n");
    return true;
  }

  return false;
}




static int add_recv(struct ctx *ctx, int idx)
{
  struct io_uring_sqe *sqe;
  if (get_sqe(ctx, &sqe)) return -1;

  //io_uring_prep_recv(sqe, fd, recvbuf, message_size, 0);
  //MAX_MESSAGE_LEN is limited by the
  io_uring_prep_recv_multishot(sqe, idx, NULL, MAX_MESSAGE_LEN, 0);
  //io_uring_prep_recvmsg_multishot(sqe, idx, &ctx->msg, MSG_TRUNC);
  
  sqe->flags |= IOSQE_FIXED_FILE;
  sqe->flags |= IOSQE_BUFFER_SELECT; // necessary for multishot
  sqe->buf_group = 0;

  // this is so you know that later on (cqe->user_data < BUFFERS) woukd be false, hence it would go to recv
  io_uring_sqe_set_data64(sqe, BUFFERS + 1);
  return 0;
}




  /* we’re done with the buffer, add it back */
// once a buffer is consumed/used/parsed by the user, its ownership should return to the kernel to be used
// again for some reading purpose
static void recycle_buffer(struct ctx *ctx, int idx)
{
  io_uring_buf_ring_add(ctx->buf_ring, get_buffer(ctx, idx), buffer_size(ctx), idx, io_uring_buf_ring_mask(BUFFERS), 0);
  io_uring_buf_ring_advance(ctx->buf_ring, 1);
}



static int process_cqe_send(struct ctx *ctx, struct io_uring_cqe *cqe)
{
  int idx = cqe->user_data;

  if (cqe->res < 0) fprintf(stderr, "bad send %s\n", strerror(-cqe->res));

  recycle_buffer(ctx, idx);

  return 0;
}


/*
  if (ctx->verbose) {
    struct sockaddr_in *addr = io_uring_recvmsg_name(o);
    struct sockaddr_in6 *addr6 = (void *)addr;
    char buff[INET6_ADDRSTRLEN + 1];
    const char *name;
    void *paddr;

    if (ctx->af == AF_INET6)
      paddr = &addr6->sin6_addr;
    else
      paddr = &addr->sin_addr;

    name = inet_ntop(ctx->af, paddr, buff, sizeof(buff));
    if (!name)
      name = "<INVALID>";

    fprintf(stderr, "received %u bytes %d from [%s]:%d\n",
      io_uring_recvmsg_payload_length(o, cqe->res, &ctx->msg),
      o->namelen, name, (int)ntohs(addr->sin_port));
  }
*/

static int process_cqe_recv(struct ctx *ctx, struct io_uring_cqe *cqe, int fdidx)
{
  int ret, idx;
  struct io_uring_recvmsg_out *o;
  struct io_uring_sqe *sqe;

  if (!(cqe->flags & IORING_CQE_F_MORE)) {
    ret = add_recv(ctx, fdidx);
    if (ret) return ret;
  }

  if (unlikely(cqe->res == -ENOBUFS))
    return 0;


  if (!(cqe->flags & IORING_CQE_F_BUFFER) || cqe->res < 0) {
    fprintf(stderr, "recv cqe bad res %d\n", cqe->res);

    if (cqe->res == -EFAULT || cqe->res == -EINVAL)
      fprintf(stderr, "NB: This requires a kernel version >= 6.0\n");
    
    return -1;
  }
  idx = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
  int bytes_read = cqe->res;

  //o = io_uring_recvmsg_validate(get_buffer(ctx, cqe->flags >> IORING_CQE_BUFFER_SHIFT), cqe->res, &ctx->msg);
  //if (!o) {
  //  fprintf(stderr, "bad recvmsg\n");
  //  return -1;
  //}
  
  //if (o->namelen > ctx->msg.msg_namelen) {
  //  fprintf(stderr, "truncated name\n");
  //  recycle_buffer(ctx, idx);
  //  return 0;
  //}

  // if the message is truncated
  if (o->flags & MSG_TRUNC) {
    uint32_t r = io_uring_recvmsg_payload_length(o, cqe->res, &ctx->msg);
    fprintf(stderr, "truncated msg need %u received %u\n", o->payloadlen, r);
    recycle_buffer(ctx, idx);
    return 0;
  }

  // gets most recent submission queue
  if (get_sqe(ctx, &sqe)) return -1;

  // not necessary as we don't need iovec
  /* 

  ALERT
  THIS SEEMS LIKE IT REUSES THE BUFFER IDX OF RECV CQE. AS IN, THE OLD BUFFER GETS CANNIBALIZED FOR THE NEW SEND SQE, SO IT IS REUSED.

  THAT IS WHY IDX IS ORIGINALLY cqe->flags >> IORING_CQE_BUFFER_SHIFT, WHICH IS THE RECV CQE, THEN THE SAME IDX IS USED.

  QUESTION IS, HOW DO WE LET THE SYSTEM KNOW THAT THIS IS THE RIGHT GROUPING? LIKE DO WE SET THE RECV GROUPS TO ALWAYS BE 1 AND THE SEND GROUPS TO ALWAYS BE 2

  ALERT
  ctx->send[idx].iov = (struct iovec) {
    .iov_base = io_uring_recvmsg_payload(o, &ctx->msg),
    .iov_len = io_uring_recvmsg_payload_length(o, cqe->res, &ctx->msg)
  };
  ctx->send[idx].msg = (struct msghdr) {
    .msg_namelen = o->namelen,
    .msg_name = io_uring_recvmsg_name(o),
    .msg_control = NULL,
    .msg_controllen = 0,
    .msg_iov = &ctx->send[idx].iov,
    .msg_iovlen = 1
  };*/


  // put the send buffers here
  // dont touch buf directly
  //.iov_base = io_uring_recvmsg_payload(o, &ctx->msg),
  //.iov_len = io_uring_recvmsg_payload_length(o, cqe->res, &ctx->msg)




  // this is the old code for sending, 
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


  // send bundled all of a certain group (given in sqe->buf_group)
  // fdidx is the index of the buffer that must be sent
  // len is the length of the 

  // how to set a buffer as part of a group?
  // this feature also adds support for provided buffers for send operations.
  sqe->buf_group = gid;
  //io_uring_prep_sendmsg(sqe, fdidx, &ctx->send[idx].msg, 0);
  io_uring_prep_send_bundle(sqe, fdidx, size_t len, 0);
  io_uring_sqe_set_data64(sqe, idx);
  sqe->flags |= IOSQE_FIXED_FILE;
  sqe->flags |= IOSQE_BUFFER_SELECT;

  // do not recycle until everything has completed
  return 0;
}



  io_uring_wait_cqe(ring, &cqe);
  /* IORING_CQE_F_BUFFER is set in cqe->flags, get buffer ID */
  buffer_id = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
  /* find the buffer from our buffer pool */
  buf = bufs[buffer_id];
  /* we’re done with the buffer, add it back */
  io_uring_buf_ring_add(br, bufs[buffer_id], BUF_SIZE, buffer_id, io_uring_buf_ring_mask(BUFS_IN_GROUP), 0);
  /* make it visible */
  io_uring_buf_ring_advance(br, 1);
  /* CQE has been seen */
  io_uring_cqe_seen(ring, cqe);




static int process_cqe(struct ctx *ctx, struct io_uring_cqe *cqe, int fdidx)
{
  if (cqe->user_data < BUFFERS)
    return process_cqe_send(ctx, cqe);
  else
    return process_cqe_recv(ctx, cqe, fdidx);
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
    //do { res = io_uring_submit_and_wait_timeout(&ring, &cqe, 1, tsPtr, NULL); } while (res < 0);
    io_uring_submit_and_wait(&ring, 1);

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
          int bid = cqe->flags >> IORING_CQE_BUFFER_SHIFT;

          if (unlikely(cqe->res <= 0)) {
            puts("failed buffer read");
            add_provide_buf(&ring, bid, group_id);
            close(conn_i.fd);
          } else {
            printf("%d\n",bytes_read);
            write(2,(char*)recvbuf, bytes_read);
            add_socket_write(&ring, conn_i.fd, bid, bytes_read, 0);
          }
        } else if (type == WRITE) {
          add_provide_buf(&ring, conn_i.bid, group_id);
          add_socket_read(&ring, conn_i.fd, group_id, MAX_MESSAGE_LEN, IOSQE_BUFFER_SELECT);
        } else if (type == ACCEPT) {
          int sock_conn_fd = cqe->res;

          // only read the future data when there is no error, >= 0
          if (sock_conn_fd >= 0)
            add_socket_read(&ring, sock_conn_fd, group_id, MAX_MESSAGE_LEN, IOSQE_BUFFER_SELECT);

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

  cleanup_context(&);

  return 0;
}

void add_sendfile(struct io_uring *ring, int fd_file, int64_t off_file, int fd_socket, int64_t off_socket, int bytes, unsigned flags)
{
  //https://man7.org/linux/man-pages/man3/io_uring_prep_recv.3.html

  struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
  io_uring_prep_splice(sqe, fd_file, off_file, fd_socket, off_socket, bytes, // num bytes for file to send
             0); // unsigned int splice_flags);
  io_uring_sqe_set_flags(sqe, flags);

  conn_info conn_i = {
    .fd = fd_file,
    .type = SENDFILE,
  };

  memcpy(&sqe->user_data, &conn_i, sizeof(conn_i));
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

/*
void add_socket_close(struct io_uring *ring, int fd)
{
  struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
  io_uring_prep_close(sqe, fd);
  io_uring_sqe_set_flags(sqe, flags);

  sqe->user_data = CREATE_CQE_INFO(fd, 0, CLOSE);
}
*/

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
