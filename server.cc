enum class output_type
{
    server = 0,
    client,
    database
};

/*
 * Assign 'buf' with the addr/len/buffer ID supplied
 */
IOURINGINLINE void io_uring_buf_ring_add(struct io_uring_buf_ring *br,
                     void *addr, unsigned int len,
                     unsigned short bid, int mask,
                     int buf_offset)
{
    struct io_uring_buf *buf = &br->bufs[(br->tail + buf_offset) & mask];

    buf->addr = (unsigned long) (uintptr_t) addr;
    buf->len = len;
    buf->bid = bid;
}


/*
 * Make 'count' new buffers visible to the kernel. Called after
 * io_uring_buf_ring_add() has been called 'count' times to fill in new
 * buffers.
 */
IOURINGINLINE void io_uring_buf_ring_advance(struct io_uring_buf_ring *br,
                         int count)
{
    unsigned short new_tail = br->tail + count;

    io_uring_smp_store_release(&br->tail, new_tail);
}


void io_uring_prep_multishot_accept_direct(struct io_uring_sqe *sqe,
                                          int sockfd,
                                          struct sockaddr *addr,
                                          socklen_t *addrlen,
                                          int flags);

// Min number of entries to wait for in the event loop
static constexpr unsigned NUM_WAIT_ENTRIES = 1;
// The maximum number of entries to retrieve in a single loop iteration
static constexpr unsigned CQE_BATCH_SIZE = 256;
// The size of the SQ. By default, the CQ ring will be twice this number
static constexpr unsigned NUM_SUBMISSION_QUEUE_ENTRIES = 2048;
// The size of each pre-allocated IO buffer. Power-of-2.
static constexpr unsigned IO_BUFFER_SIZE = 8192;
// The number of IO buffers to pre-allocate
static constexpr uint16_t NUM_IO_BUFFERS = 4096;


static inline int setup_sock(int port)
{
    struct sockaddr_in serv_addr;
    int sock_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    const int val = 1;

    if (setsockopt(sock_listen_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT | SO_ZEROCOPY, &val, sizeof(val))) {
        perror("setsockopt");
        exit(1);
    }

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


int setup_buffers(group_id)
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

/*
    struct io_uring_buf_ring *io_uring_setup_buf_ring(struct io_uring *ring,
                               unsigned int nentries,
                               int bgid,
                               unsigned int flags,
                               int *ret);
*/
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


void register_file_table()
{
    io_uring_register_files_sparse(ring, NR_FILES);
}


int setup_params(struct ctx *ctx)
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

    ret = setup_buffers(ctx);
    if (ret) io_uring_queue_exit(&ctx->ring);


    // check if IORING_FEAT_FAST_POLL is supported
    if (!(params.features & IORING_FEAT_FAST_POLL)) {
        printf("IORING_FEAT_FAST_POLL not available in the kernel, quiting...\n");
        exit(0);
    }

    memset(&ctx->msg, 0, sizeof(ctx->msg));
    ctx->msg.msg_namelen = sizeof(struct sockaddr_storage);
    ctx->msg.msg_controllen = CONTROLLEN;

    if (io_uring_register_ring_fd(&ring) != 1) {
        return ;
    }

    return ret;
}


static void recycle_buffer(io_uring_buf_ring* br, uint8_t* buf_base_addr, uint16_t idx) {
    // https://man7.org/linux/man-pages/man3/io_uring_buf_ring_add.3.html
    // buf_offset is the offset to insert at from the current tail. If just one buffer is
    // provided before the tail is committed with io_uring_buf_ring_advance(3) or
    // io_uring_buf_ring_cq_advance(3), then buf_offset should be 0
    

    //io_uring_buf_ring_add(buf_ring, buf_base_addr + (idx << log2<UringEchoServer::IO_BUFFER_SIZE>()), UringEchoServer::IO_BUFFER_SIZE, idx,
    //                      io_uring_buf_ring_mask(UringEchoServer::NUM_IO_BUFFERS), /* buf_offset */ 0);
    io_uring_buf_ring_add(br, buf_base_addr + (1U << BUFSIZE_SHIFT) * i, 1U << BUFSIZE_SHIFT, i, io_uring_buf_ring_mask(NUM_BUFFERS), 0);

    // Make the buffer visible to the kernel
    io_uring_buf_ring_advance(br, 1);
}


/*

So there is now a pretty big difference between the received and send buffers.

For the receive buffers, you have to initially add all of them into the kernel,
For the send buffers you actually add none of them initially and only slowly do you start adding them to the kernel
 
You only add them to the kernel when you are about to send

By having two separate buffers as well as different buffer groups, you will not have interference between the send and receive side 

*/

void add_socket_close(struct io_uring *ring, int fd)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    io_uring_prep_close(sqe, fd);
    io_uring_sqe_set_flags(sqe, flags);

    sqe->user_data = CREATE_CQE_INFO(fd, 0, CLOSE);
}

int process_cqe_send(const char*)
{
    int idx = cqe->user_data;
    recycle_buffer(ctx, idx);
    return 0;
}

static int add_recv(int idx)
{
    struct io_uring_sqe *sqe = get_sqe();

    io_uring_prep_recv_multishot(sqe, idx, NULL, MAX_MESSAGE_LEN, 0);
    io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE | IOSQE_BUFFER_SELECT);
    sqe->buf_group = 0;

    io_uring_sqe_set_data64(sqe, BUFFERS + 1);
    return 0;
}

int process_cqe_recv(io_uring_cqe* cqe)
{
    int ret, idx;
    struct io_uring_recvmsg_out *o;

    // how to deal with flags?
    if (!(cqe->flags & IORING_CQE_F_MORE)) {
        ret = add_recv(ctx, fdidx);
        if (ret) return ret;
    }

    if (!(cqe->flags & IORING_CQE_F_BUFFER) || cqe->res < 0) {
        fprintf(stderr, "recv cqe bad res %d\n", cqe->res);

        if (cqe->res == -EFAULT || cqe->res == -EINVAL)
            fprintf(stderr, "NB: This requires a kernel version >= 6.0\n");

        return -1;
    }

    idx = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
    int bytes_read = cqe->res;

    // if the message is truncated
    // deal with by issuing coalesce
    // possibly if this file is giant, 
    // then do not save to memory but rather to file
    if (o->flags & MSG_TRUNC) {
        uint32_t r = io_uring_recvmsg_payload_length(o, cqe->res, &ctx->msg);
        fprintf(stderr, "truncated msg need %u received %u\n", o->payloadlen, r);
        recycle_buffer(idx);
        return 0;
    }

    // gets most recent submission queue
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);

    /* 

    THIS SEEMS LIKE IT REUSES THE BUFFER IDX OF RECV CQE. AS IN, THE OLD BUFFER GETS CANNIBALIZED FOR THE NEW SEND SQE, SO IT IS REUSED.

    THAT IS WHY IDX IS ORIGINALLY cqe->flags >> IORING_CQE_BUFFER_SHIFT, WHICH IS THE RECV CQE, THEN THE SAME IDX IS USED.

    */


    // send bundled all of a certain group (given in sqe->buf_group)
    // fdidx is the index of the buffer that must be sent
    // len is the length of the 

    // how to set a buffer as part of a group?
    // this feature also adds support for provided buffers for send operations.
    sqe->buf_group = gid;
    recycle_buffer(idx);

    //diff betw the two is that first one requires a registered sockfd in the index array, while the second does not need that
    //io_uring_prep_send_zc(sqe, sockfd, buf, len,  flags,  zc_flags);
    io_uring_prep_send_zc_fixed(sqe, sockfd_idx, buf, len, flags, zc_flags, buf_index);
    conn_info conn_i = {
        .fd = fd,
        .type = WRITE,
        .bid = bid,
    };
    io_uring_sqe_set_data64(sqe, uint64_t(conn_i));
    io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE | IOSQE_BUFFER_SELECT);
    return 0;
}

void cleanup_context()
{
    munmap(ctx->buf_ring, buf_ring_size);
    io_uring_queue_exit(&ctx->ring);
}

void server::evloop()
{
    unsigned head;
    unsigned count = 0;

    // start event loop
    while (1) {
        //do { res = io_uring_submit_and_wait_timeout(&ring, &cqe, 1, tsPtr, NULL); } while (res < 0);
        io_uring_submit_and_wait(&ring, 1);


        const unsigned num_cqes = io_uring_peek_batch_cqe(&ring_, cqes, CQE_BATCH_SIZE);
        for (unsigned cqe_idx = 0; cqe_idx < num_cqes; ++cqe_idx) {
            io_uring_cqe* cqe = cqes[cqe_idx];
            const auto ctx = get_context(cqe);

            switch (ctx.type) {
                case ContextType::Accept:
                    handle_accept(cqe);
                    break;
                case ContextType::Close:
                    // No-op
                    LOG_INFO("Closed: %d\n", ctx.client_fd);
                    break;
                case ContextType::Read:
                    handle_read(cqe, ctx.client_fd);
                    break;
                case ContextType::Write:
                    handle_write(cqe, ctx.client_fd, ctx.buffer_idx);
                    break;
                default:
                    error(EXIT_ERROR, 0, "context type not handled: %d", static_cast<int>(ctx.type));
                    break;
            }
        }
        

        // go through all CQEs
        io_uring_for_each_cqe(&ring, head, cqe) {
            ++count;
            uint64_t ud = cqe->user_data;

            if (type == READ) {
                process_cqe_recv(cqe);
            } else if (type == WRITE) {
                process_cqe_send();
            } else if (type == ACCEPT) {
                // only read the future data when there is no error, >= 0
                //IORING_CQE_F_MORE
                if (cqe->res >= 0) {
                    if (!(cqe->flags & IORING_CQE_F_MORE)) {
                        ret = add_accept(ctx, fdidx);
                    }

                    add_recv();
                }
            }
        }

        io_uring_cq_advance(&ring, count);

        // now send all the messages to users that were accumulated in the send_queue.
    }
}


int main()
{
    server srv;
    srv.setup();
    srv.evloop();
}

