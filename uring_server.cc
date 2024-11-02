#include "uring_server.hh"

#include <cstdlib>
#include <cstring>
#include <cstdio>

// Linux
#include <error.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>

static inline int setup_socket(int port)
{
    int sock_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    
    const int val = 1;
    if (setsockopt(sock_listen_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT | SO_ZEROCOPY, &val, sizeof(val))) {
        perror("setsockopt");
        exit(1);
    }

    struct sockaddr_in serv_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr = { INADDR_ANY }
    };

    // bind and listen
    if (bind(sock_listen_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Error binding socket...\n");
        exit(1);
    }

    if (listen(sock_listen_fd, SOMAXCONN) < 0) {
        perror("Error listening on socket...\n");
        exit(1);
    }

    return sock_listen_fd;
}

static inline void init_io_uring(io_uring* ring, unsigned num_submission_queue_entries)
{
    io_uring_params params;
    memset(&params, 0, sizeof(params));
    //params.cq_entries = QD * 8;
    //IORING_SETUP_SINGLE_ISSUER can only be used with single thread
    params.flags = (IORING_SETUP_DEFER_TASKRUN) | (IORING_SETUP_SUBMIT_ALL | IORING_SETUP_COOP_TASKRUN | IORING_SETUP_CQSIZE);

    //  On success, io_uring_queue_init(3) returns 0 and 'ring' will point to the shared memory containing the
    //  io_uring queues. On failure -errno is returned.
    int ret = io_uring_queue_init_params(num_submission_queue_entries, ring, &params);
    if (ret != 0) {
        perror("io_uring_queue_init_params");
        exit(1);
    }

    // check if IORING_FEAT_FAST_POLL is supported
    if (!(params.features & IORING_FEAT_FAST_POLL)) {
        perror("IORING_FEAT_FAST_POLL not available in the kernel, quiting...\n");
        exit(1);
    }

    if (io_uring_register_ring_fd(ring) != 1) {
        perror("io_uring_register_ring_fd\n");
        exit(1);
    }
}


static constexpr unsigned buffer_ring_size()
{
    return (IO_BUFFER_SIZE + sizeof(io_uring_buf)) * NUM_IO_BUFFERS;
}

static constexpr uint8_t* get_buffer_base_addr(void* ring_addr)
{
    return (uint8_t*)ring_addr + (sizeof(io_uring_buf) * NUM_IO_BUFFERS);
}

static constexpr uint8_t* get_buffer_addr(uint8_t* base_addr, uint16_t idx)
{
    return base_addr + (idx * IO_BUFFER_SIZE);
}

// Pretty much a copy-paste from:
// https://github.com/axboe/liburing/blob/master/examples/io_uring-udp.c
static uint8_t* init_buffer_ring(io_uring* ring, io_uring_buf_ring** buf_ring, size_t ring_size)
{
    // https://man7.org/linux/man-pages/man3/io_uring_register_buf_ring.3.html
    // The ring_addr field must contain the address to the memory
    // allocated to fit this ring. The memory must be page aligned and
    // hence allocated appropriately using eg posix_memalign(3) or
    // similar. The size of the ring is the product of ring_entries and
    // the size of struct io_uring_buf. ring_entries is the desired
    // size of the ring, and must be a power-of-2 in size. The maximum
    // size allowed is 2^15 (32768). bgid is the buffer group ID
    // associated with this ring. SQEs that select a buffer have a
    // buffer group associated with them in their buf_group field, and
    // the associated CQEs will have IORING_CQE_F_BUFFER set in their
    // flags member, which will also contain the specific ID of the
    // buffer selected. The rest of the fields are reserved and must be
    // cleared to zero.

    // From: https://unixism.net/loti/ref-iouring/io_uring_register.html
    // Currently, the buffers must be anonymous, non-file-backed memory, such as that returned by malloc(3) or
    // mmap(2) with the MAP_ANONYMOUS flag set. It is expected that this limitation will be lifted in the
    // future
    void* ring_addr =
        mmap(/* addr */ nullptr, ring_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
    // mmap: If addr is nullptr, then the kernel chooses the (page-aligned) address at which to create the
    // mapping
    if (ring_addr == MAP_FAILED) {
        perror("mmap ring");
        exit(-1);
    }

    io_uring_buf_reg reg{};
    memset(&reg, 0, sizeof(reg));
    reg.ring_addr = reinterpret_cast<__u64>(ring_addr);
    reg.ring_entries = NUM_IO_BUFFERS;
    reg.bgid = BUFFER_GROUP_ID;

    const unsigned flags = 0;
    const int register_buf_ring_result = io_uring_register_buf_ring(ring, &reg, flags);
    if (register_buf_ring_result != 0) {
        perror("io_uring_register_buf_ring");
        exit(-register_buf_ring_result);
    }

    *buf_ring = reinterpret_cast<io_uring_buf_ring*>(ring_addr);
    io_uring_buf_ring_init(*buf_ring);

    // Start of the actual buffer memory
    uint8_t* buffer_base_addr = get_buffer_base_addr(ring_addr);

    // Add all buffers to a shared buffer ring
    for (uint16_t buffer_idx = 0u; buffer_idx < NUM_IO_BUFFERS; ++buffer_idx) {
        // https://man7.org/linux/man-pages/man3/io_uring_buf_ring_add.3.html
        io_uring_buf_ring_add(*buf_ring, get_buffer_addr(buffer_base_addr, /* bid */ buffer_idx),
                              IO_BUFFER_SIZE, buffer_idx,
                              io_uring_buf_ring_mask(NUM_IO_BUFFERS),
                              /* buf_offset */ buffer_idx);
    }

    // Make 'count' new buffers visible to the kernel. Called after io_uring_buf_ring_add() has been called
    // 'count' times to fill in new buffers.
    io_uring_buf_ring_advance(*buf_ring, NUM_IO_BUFFERS);

    return buffer_base_addr;
}


uring_server::uring_server(uint16_t port)
{
    listening_socket_ = setup_socket(port);
    init_io_uring(&ring_, NUM_SUBMISSION_QUEUE_ENTRIES);
    ring_initialized_ = true;

    // Init the shared IO buffers
    constexpr size_t ring_size = buffer_ring_size();
    buf_ring_size_ = ring_size;
    io_buffers_base_addr_ = init_buffer_ring(&ring_, &buf_ring_, ring_size);

    // register files()
    //if (io_uring_register_files_sparse(&ring_, NUM_FILES_REGISTERED) != 0) {
    //    perror("io_uring_register_files_sparse");
    //    exit(-1);
    //}
}

uring_server::~uring_server()
{
    if (buf_ring_ != nullptr) {
        munmap(buf_ring_, buf_ring_size_);
    }

    if (ring_initialized_) {
        io_uring_queue_exit(&ring_);
    }

    if (listening_socket_ != -1) {
        close(listening_socket_);
    }
}


io_uring_sqe* uring_server::get_sqe()
{
    // returns a pointer to the next submission queue event on success and NULL on failure.
    // If NULL is returned, the SQ ring is currently full and entries must be submitted for processing before
    // new ones can get allocated
    io_uring_sqe* sqe = io_uring_get_sqe(&ring_);
    if (sqe == nullptr) [[unlikely]] {
        io_uring_submit(&ring_);
        sqe = io_uring_get_sqe(&ring_);
    }

    if (sqe == nullptr) [[unlikely]] {
        perror("io_uring_get_sqe\n");
        exit(1);
    }

    return sqe;
}


/*

int uring_server::setup_buffers(int group_id)
{
    //The size of the ring is the product of ring_entries and the size of struct io_uring_buf
    buf_ring_size = (sizeof(struct io_uring_buf) + buffer_size(ctx)) * BUFFERS;

    uint8_t* mapped = (uint8_t*)mmap(NULL, buf_ring_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
    if (mapped == MAP_FAILED) {
        fprintf(stderr, "buf_ring mmap: %s\n", strerror(errno));
        return -1;
    }

    // buf_ring is the beginning 
    ctx->buf_ring = (struct io_uring_buf_ring *)mapped;

    //struct io_uring_buf_ring *io_uring_setup_buf_ring(struct io_uring *ring,
    //                           unsigned int nentries,
    //                           int bgid,
    //                           unsigned int flags,
    //                           int *ret);
    io_uring_buf_ring_init(ctx->buf_ring);

    // the BGID here is needed to identify the recvs and sends...
    struct io_uring_buf_reg reg = {
        .ring_addr = (uint64_t)ctx->buf_ring,
        .ring_entries = BUFFERS,
        .bgid = group_id
    };

    // buffer_base is 
    ctx->buffer_base = (uint8_t *)ctx->buf_ring + sizeof(struct io_uring_buf) * BUFFERS;

    // flags must be 0
    int ret = io_uring_register_buf_ring(&ctx->ring, &reg, 0);
    if (ret) {
        fprintf(stderr, "buf_ring init failed: %s\n" "NB This requires a kernel version >= 6.0\n", strerror(-ret));
        return ret;
    }

    for (int i = 0; i < BUFFERS; ++i)
        io_uring_buf_ring_add(buf_ring, mapped + (1U << buf_shift) * i, 1U << buf_shift, i, io_uring_buf_ring_mask(BUFFERS), i);

    // advance buffer
    io_uring_buf_ring_advance(ctx->buf_ring, BUFFERS);

    return 0;
}
*/

static void recycle_buffer(io_uring_buf_ring* br, uint8_t* buf_base_addr, uint16_t idx)
{
    // https://man7.org/linux/man-pages/man3/io_uring_buf_ring_add.3.html
    // buf_offset is the offset to insert at from the current tail. If just one buffer is
    // provided before the tail is committed with io_uring_buf_ring_advance(3) or
    // io_uring_buf_ring_cq_advance(3), then buf_offset should be 0

    //io_uring_buf_ring_add(buf_ring, buf_base_addr + (idx << log2<uring_server::IO_BUFFER_SIZE>()), uring_server::IO_BUFFER_SIZE, idx,
    //                      io_uring_buf_ring_mask(NUM_IO_BUFFERS), /* buf_offset */ 0);
    io_uring_buf_ring_add(br, get_buffer_addr(buf_base_addr, idx), IO_BUFFER_SIZE, idx, io_uring_buf_ring_mask(NUM_IO_BUFFERS), 0);
//IO_BUFFER_SIZE, idx,io_uring_buf_ring_mask(NUM_IO_BUFFERS), 
    // Make the buffer visible to the kernel
    io_uring_buf_ring_advance(br, 1);
}





























void uring_server::handle_send(io_uring_cqe* cqe, int client_fd_idx, uint16_t buffer_idx)
{
    const auto result = cqe->res;
    
    if (result == -EPIPE || result == -EBADF || result == -ECONNRESET) [[unlikely]] {
        // EPIPE - Broken pipe
        // ECONNRESET - Connection reset by peer
        // EBADF - Fd has been closed
        add_close(client_fd_idx);
    } else if (result < 0) {
        printf("Write error: %d\n", result);
    }

    recycle_buffer(buf_ring_, io_buffers_base_addr_, buffer_idx);
}

/////////
///////// client_fd is actually an idx
void uring_server::handle_accept(io_uring_cqe* cqe, int client_fd_idx, uint16_t placeholder)
{
    //const auto client_fd = cqe->res;

    if (!flag_is_set(cqe, IORING_CQE_F_MORE)) [[unlikely]] {
        // The current accept will not produce any more entries, add a new one
        add_accept();
    }

    if (client_fd_idx >= 0) [[likely]] {
        // Valid fd, start reading
        add_recv(client_fd_idx);
        printf("New connection: %d\n", client_fd_idx);
    } else {
        printf("Accept error: %d\n", client_fd_idx);
    }
}

void uring_server::handle_recv(io_uring_cqe* cqe, int client_fd_idx, uint16_t placeholder)
{
    const auto result = cqe->res;
    bool closed = false;

    if (result > 0) [[likely]] {
        // We read some data. Yay!
        if (!flag_is_set(cqe, IORING_CQE_F_BUFFER)) [[unlikely]] {
            // No buffer flag set, not sure this can happen(?)...
            add_close(client_fd_idx); // Brute force close for now
            closed = true;
        } else {
            const uint16_t buffer_idx = cqe->flags >> 16;
            const void* addr = get_buffer_addr(io_buffers_base_addr_, buffer_idx);

            //recycle_buffer(buf_ring_, io_buffers_base_addr_, idx);

            printf("Read %d bytes on fd: %d\n", result, client_fd_idx);

            // Echo the data we just read (DO WE NEED A BUF_GROUP) // sqe->buf_group = gid;
            add_send(client_fd_idx, addr, result, buffer_idx);
        }
    } else { // Error
        // EOF, Broken pipe or Connection reset by peer
        if ((result != -ENOBUFS) && (result == 0 || result == -EBADF || result == -ECONNRESET)) { [[unlikely]]
            add_close(client_fd_idx);
            closed = true;
        }
    }

    // if this is closed, we do not add any more
    if (!closed && !flag_is_set(cqe, IORING_CQE_F_MORE)) [[unlikely]] {
        // The current recv will not produce any more entries, add a new one
        add_recv(client_fd_idx);
    }
}

/*

So there is now a pretty big difference between the received and send buffers.

For the receive buffers, you have to initially add all of them into the kernel,
For the send buffers you actually add none of them initially and only slowly do you start adding them to the kernel
 
You only add them to the kernel when you are about to send

By having two separate buffers as well as different buffer groups, you will not have interference between the send and receive side 

*/

void uring_server::evloop()
{
    io_uring_cqe* cqe;
    unsigned head = 0;
    unsigned count = 0;
    user_data_t ud;

    add_accept();

#if CQE_HANDLER_STYLE==CQE_HANDLER_FUNCTION_TABLE
    typedef void (uring_server::*handle_func_t)(io_uring_cqe*, int, uint16_t);
    handle_func_t hfcs[] = { &uring_server::handle_recv, &uring_server::handle_send, &uring_server::handle_send, &uring_server::handle_accept };
#endif

    // start event loop
    while (1) {
        //do { res = io_uring_submit_and_wait_timeout(&ring_, &cqe, 1, tsPtr, NULL); } while (res < 0);
        io_uring_submit_and_wait(&ring_, 1);
        

        io_uring_for_each_cqe(&ring_, head, cqe) {
            ++count;

            ud.value = cqe->user_data;

#if CQE_HANDLER_STYLE==CQE_HANDLER_FUNCTION_TABLE
            (this->*hfcs[ud.bitfield.type & 3])(cqe, ud.bitfield.client_fd, ud.bitfield.buffer_idx);

#elif CQE_HANDLER_STYLE==CQE_HANDLER_IF_CHAIN
            if (ud.bitfield.type == URING_OP::ACCEPT)
                handle_accept(cqe, cqe->res,  -1);
            else if (ud.bitfield.type == URING_OP::RECV)
                handle_recv(cqe, ud.bitfield.client_fd,  -1);
            else if (ud.bitfield.type == URING_OP::SEND)
                handle_write(cqe, ud.bitfield.client_fd, ud.bitfield.buffer_idx);
#endif
        }

        io_uring_cq_advance(&ring_, count);
        // now send all the messages to users that were accumulated in the send_queue.
    }
}

int main()
{

    printf("%zu\n", sizeof(io_uring));

    //uring_server srv(8095);
    //srv.evloop();

    return 0;
}
