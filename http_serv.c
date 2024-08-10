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

#define MAX_CONNECTIONS     1024
#define BACKLOG             512
#define MAX_MESSAGE_LEN     4096
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



int parse()
{
  uint64_t verb_str = *(uint64_t*)p;

  if (substr4i(verb_str) == str4i('G','E','T',' ')) { verb = 0; p += 4; }
  else if (substr5i(verb_str) == str5i('P','O','S','T',' ')) { verb = 1; p += 5; }
  else if (substr4i(verb_str) == str4i('P','U','T',' ')) { verb = 2; p += 4; }
  else if (substr7i(verb_str) == str7i('D','E','L','E','T','E',' ')) { verb = 3; p += 7; }
  else if (        (verb_str) == str8i('O','P','T','I','O','N','S',' ')) { verb = 4; p += 8; }
  else { return 1; }

  if (p == '/') {
    char* fvalue = p;
    // replace with memchr
    while (*p != ' ') ++p;
    char* host_end = p;
    size_t host_len = host_end - host;

    host_value = pair(host,host_len);
  } else {
    return 2;
  }

  uint64_t verb_str = *(uint64_t*)p;
  if (         (verb_str) == u64_str8('H','T','T','P','/','1','.','1')) { verb = 4; p += 8; }
  if (         (verb_str) == u64_str8('H','T','T','P','/','1','.','0')) { verb = 4; p += 8; }

  for (memcmp(p, "\r\n\r\n", 4) == 0) {
    if (memcmp(p, "Host: ", 6) == 0) {
      p += 6;

      char* host = p;
      while (*p != '\r' && *p != '\n') ++p;
      char* host_end = p;
      size_t host_len = host_end - host;

      host_value = pair(host,host_len);
    } else {
      char* fname = p;
      while (*p != ':') ++p;
      char* fname_end = p;
      size_t host_len = fname_end - fname;

      ++p;
      if (*p == ' ') ++p;

      char* fvalue = p;
      while (*p != '\r' && *p != '\n') ++p;
      char* host_end = p;
      size_t host_len = host_end - host;

      host_value = pair(host,host_len);

      header[pair(name,name_len)] = pair(value,value_len);
    }

    if (memcmp(p, "\r\n", 2) == 0) {
      p += 2;
    }
  }

}



#define FRAME_HEADER_SIZE 9

// Define a structure for an HTTP/2 frame header
typedef struct {
    uint32_t length;
    uint8_t type;
    uint8_t flags;
    uint32_t stream_id;
    uint8_t *payload;
} http2_frame;

// Function to parse an HTTP/2 frame header
int parse_http2_frame(const uint8_t *data, size_t data_len, http2_frame *frame) {
    if (data_len < FRAME_HEADER_SIZE) {
        return -1; // Not enough data to parse the header
    }

    // Extract the length (24 bits)
    frame->length = (data[0] << 16) | (data[1] << 8) | data[2];

    // Extract the type (8 bits)
    frame->type = data[3];

    // Extract the flags (8 bits)
    frame->flags = data[4];

    // Extract the Stream Identifier (31 bits, ignore the first bit)
    frame->stream_id = ((data[5] & 0x7F) << 24) | (data[6] << 16) | (data[7] << 8) | data[8];

    // Extract the payload
    if (data_len < FRAME_HEADER_SIZE + frame->length) {
        return -1; // Not enough data for the payload
    }
    frame->payload = (uint8_t *)malloc(frame->length);
    if (!frame->payload) {
        return -1; // Memory allocation failure
    }
    memcpy(frame->payload, data + FRAME_HEADER_SIZE, frame->length);

    return 0; // Success
}

// Function to free an HTTP/2 frame
void free_http2_frame(http2_frame *frame) {
    if (frame->payload) {
        free(frame->payload);
        frame->payload = NULL;
    }
}


int parse_http2()
{
    // Example HTTP/2 frame data (length: 5, type: 1, flags: 0, stream_id: 1, payload: "Hello")
    uint8_t data[] = {0x00, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 'H', 'e', 'l', 'l', 'o'};
    size_t data_len = sizeof(data);

    http2_frame frame;
    if (parse_http2_frame(data, data_len, &frame) == 0) {
        printf("Parsed HTTP/2 frame:\n");
        printf("Length: %u\n", frame.length);
        printf("Type: %u\n", frame.type);
        printf("Flags: %u\n", frame.flags);
        printf("Stream ID: %u\n", frame.stream_id);
        printf("Payload: ");
        for (uint32_t i = 0; i < frame.length; i++) {
            printf("%c", frame.payload[i]);
        }
        printf("\n");

        free_http2_frame(&frame);
    } else {
        printf("Failed to parse HTTP/2 frame\n");
    }

    return 0;
}


// UNUSED YET
struct io_uring_buf_ring *setup_buffer_ring(struct io_uring *ring)
{
  struct io_uring_buf_reg reg = { };
  struct io_uring_buf_ring *br;
  int i;

  /* allocate mem for sharing buffer ring */
  if (posix_memalign((void **) &br, 4096,
         BUFS_IN_GROUP * sizeof(struct io_uring_buf_ring)))
    return NULL;

  /* assign and register buffer ring */
  reg.ring_addr = (unsigned long) br;
  reg.ring_entries = BUFS_IN_GROUP;
  reg.bgid = BUF_BGID;
  if (io_uring_register_buf_ring(ring, &reg, 0))
    return 1;

  /* add initial buffers to the ring */
  io_uring_buf_ring_init(br);
  for (i = 0; i < BUFS_IN_GROUP; i++) {
    /* add each buffer, we'll use i buffer ID */
    io_uring_buf_ring_add(br, bufs[i], BUF_SIZE, i,
              io_uring_buf_ring_mask(BUFS_IN_GROUP), i);
  }

  /* we've supplied buffers, make them visible to the kernel */
  io_uring_buf_ring_advance(br, BUFS_IN_GROUP);
  return br;
}



int get_socket(int portno)
{
  struct sockaddr_in serv_addr;

  // setup socket
  int sock_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
  const int val = 1;

  if (setsockopt(sock_listen_fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)))
    perror("setsockopt reuseaddr");

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

/*
const char* req = 
"POST / HTTP/1.1\r\n"
"User-Agent: test\r\n"
"Content-Length: 13\r\n"
"\r\n"
"Hello, world!";*/

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

    do {res = io_uring_submit_and_wait_timeout(&ring, &cqe, 1, tsPtr, NULL);} while (res < 0);

    //struct io_uring_cqe *cqe;
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

void add_register_buf_ring(struct io_uring *ring, __u16 bid, unsigned gid)
{
  struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
  io_uring_prep_provide_buffers(sqe, bufs[bid], MAX_MESSAGE_LEN, 1, gid, bid);

  conn_info conn_i = {
    .fd = 0,
    .type = PROV_BUF,
  };

  memcpy(&sqe->user_data, &conn_i, sizeof(conn_i));





  struct io_uring_buf_reg reg = { };
  struct io_uring_buf_ring *br;
  int i;

  /* allocate mem for sharing buffer ring */
  if (posix_memalign((void **) &br, 4096,
         BUFS_IN_GROUP * sizeof(struct io_uring_buf_ring)))
    return NULL;

  /* assign and register buffer ring */
  reg.ring_addr = (unsigned long) br;
  reg.ring_entries = BUFS_IN_GROUP;
  reg.bgid = BUF_BGID;
  if (io_uring_register_buf_ring(ring, &reg, 0))
    return 1;



}
