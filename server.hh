

struct server
{
    struct io_uring ring;
    struct io_uring_buf_ring *buf_ring;
    unsigned char *buffer_base;
    struct msghdr msg;
    int buf_shift;
    int af;
    bool verbose;
    struct sendmsg_ctx send[BUFFERS];
    size_t buf_ring_size;



    int listening_socket_ = -1;
    io_uring ring_{};
    io_uring_buf_ring* buf_ring_ = nullptr;
    size_t buf_ring_size_ = 0;
    uint8_t* io_buffers_base_addr_ = nullptr;
    bool ring_initialized_ = false;

    // This will be filled with the address of the peer on accept events
    // We currently use io_uring_prep_multishot_accept so this value might get overridden i.e.
    // these fields are not really usable...
    sockaddr_in client_addr_{};
    socklen_t client_addr_len_ = sizeof(client_addr_);

public:
    server();

    int process_rate_limit();

    int setup_buffers();

    void evloop();



    void handle_accept(io_uring_cqe* cqe);
    void handle_read(io_uring_cqe* cqe, int client_fd);
    void handle_write(io_uring_cqe* cqe, int client_fd, uint16_t buffer_idx);

    inline io_uring_sqe* get_sqe()
    {
        // returns a pointer to the next submission queue event on success and NULL on failure.
        // If NULL is returned, the SQ ring is currently full and entries must be submitted for processing before
        // new ones can get allocated
        io_uring_sqe* sqe = io_uring_get_sqe(&ring_);
        if (sqe == nullptr) {
            io_uring_submit(&ring_);
            sqe = io_uring_get_sqe(&ring_);
        }

        if (sqe == nullptr) {
            error(EXIT_ERROR, 0, "io_uring_get_sqe");
        }

        return sqe;
    }

    void add_accept(struct io_uring *ring, int fd, struct sockaddr *client_addr, socklen_t *client_len)
    {
        struct io_uring_sqe *sqe = io_uring_get_sqe(ring);

        io_uring_prep_multishot_accept_direct(sqe, sockfd_idx, client_addr, client_len, 0);
        io_uring_sqe_set_flags(sqe, flags);
        conn_info conn_i = {
            .fd = fd,
            .type = ACCEPT,
        };

        memcpy(&sqe->user_data, &conn_i, sizeof(conn_i));
    }


    void add_close(int client_fd)
    {
        io_uring_sqe* sqe = get_sqe();
        
        io_uring_sqe_set_flags(sqe, IOSQE_CQE_SKIP_SUCCESS);
        set_context(sqe, ContextType::Close, client_fd, IOSQE_CQE_SKIP_SUCCESS);
        io_uring_prep_close(sqe, client_fd);
    }

    void add_recv(int client_fd)
    {
        struct io_uring_sqe *sqe;
        if (get_sqe(ctx, &sqe)) return -1;

        //io_uring_prep_recv(sqe, fd, recvbuf, message_size, 0);
        //MAX_MESSAGE_LEN is limited by the
        io_uring_prep_recv_multishot(sqe, idx, NULL, MAX_MESSAGE_LEN, 0);

        sqe->flags |= IOSQE_FIXED_FILE;
        sqe->flags |= IOSQE_BUFFER_SELECT; // necessary for multishot
        sqe->buf_group = 0;

        // this is so you know that later on (cqe->user_data < BUFFERS) woukd be false, hence it would go to recv
        io_uring_sqe_set_data64(sqe, BUFFERS + 1);
        return 0;




        io_uring_sqe* sqe = get_sqe();
        set_context(sqe, ContextType::Read, client_fd, /* buffer_idx */ 0u);
        io_uring_prep_recv_multishot(sqe, client_fd, nullptr, 0, 0);

        sqe->flags |= IOSQE_FIXED_FILE;
        sqe->flags |= IOSQE_BUFFER_SELECT; // necessary for multishot

        sqe->buf_group = BUFFER_GROUP_ID;
    }

    void add_write(int client_fd, const void* data, unsigned length, uint16_t buffer_idx)
    {

    }

};

