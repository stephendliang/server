

struct server
{
    //struct io_uring ring;
    //struct io_uring_buf_ring *buf_ring;
    unsigned char *buffer_base;
    struct msghdr msg;
    int buf_shift;
    int af;
    bool verbose;
    struct sendmsg_ctx send[BUFFERS];
    size_t buf_ring_size;



    int listening_socket_ = -1;
    io_uring ring_;
    io_uring_buf_ring* buf_ring_;

    size_t buf_ring_size_ = 0;
    uint8_t* io_buffers_base_addr_ = nullptr;
    bool ring_initialized_ = false;

    // This will be filled with the address of the peer on accept events
    // We currently use io_uring_prep_multishot_accept so this value might get overridden i.e.
    // these fields are not really usable...
    sockaddr_in client_addr_;
    socklen_t client_addr_len_ = sizeof(client_addr_);

public:
    server();

    int process_rate_limit();

    int setup_buffers();

    void evloop();

    void handle_accept(io_uring_cqe* cqe)
    {
        const auto client_fd = cqe->res;

        if (client_fd >= 0) [[likely]] {
            // Valid fd, start reading
            add_recv(client_fd);
            LOG_INFO("New connection: %d\n", client_fd);
        } else {
            LOG_ERROR("Accept error: %d\n", client_fd);
        }

        if (!flag_is_set(cqe, IORING_CQE_F_MORE)) [[unlikely]] {
            // The current accept will not produce any more entries, add a new one
            add_accept();
        }
    }

    void handle_read(io_uring_cqe* cqe, int client_fd)
    {
        const auto result = cqe->res;
        bool closed = false;

        if (result > 0) [[likely]] { 
            // We read some data. Yay!
            if (!flag_is_set(cqe, IORING_CQE_F_BUFFER)) [[unlikely]] {
                // No buffer flag set, not sure this can happen(?)...
                add_close(client_fd); // Brute force close for now
                closed = true;
            } else {
                const uint16_t buffer_idx = cqe->flags >> 16;
                const void* addr = get_buffer_addr(io_buffers_base_addr_, buffer_idx);
    
                recycle_buffer(idx);???



                LOG_INFO("Read %d bytes on fd: %d\n", result, client_fd);

                // Echo the data we just read
                add_write(client_fd, addr, result, buffer_idx);
            }
        } else {
            // Error
            //LsOG_ERROR("Recv error: %d\n", result);
            if (result == 0 || result == -EBADF || result == -ECONNRESET) { [[unlikely]] // EOF, Broken pipe or Connection reset by peer
                add_close(client_fd);
                closed = true;
            } 

            if (result == -ENOBUFS) {
                // No buffer to read data into...
            } else {
                add_close(client_fd); // Brute force close for now
                closed = true;
            }
        }

        // if this is closed, we do not add any more
        if (!closed && !flag_is_set(cqe, IORING_CQE_F_MORE)) [[unlikely]] {
            // The current recv will not produce any more entries, add a new one
            add_recv(client_fd);
        }
    }


    void handle_send(io_uring_cqe* cqe, int client_fd, uint16_t buffer_idx)
    {
        const auto result = cqe->res;
        if (result == -EPIPE || result == -EBADF || result == -ECONNRESET) [[unlikely]] {
            // EPIPE - Broken pipe
            // ECONNRESET - Connection reset by peer
            // EBADF - Fd has been closed
            add_close(client_fd);
        } else if (result < 0) {
            // some other error
        }

        recycle_buffer(buf_ring_, io_buffers_base_addr_, buffer_idx);
    }

    void UringEchoServer::handle_write(io_uring_cqe* cqe, int client_fd, uint16_t buffer_idx) {
        const auto result = cqe->res;
        if (result == -EPIPE || result == -EBADF || result == -ECONNRESET) {
            // EPIPE - Broken pipe
            // ECONNRESET - Connection reset by peer
            // EBADF - Fd has been closed
            add_close(client_fd);
        } else if (result < 0) {
            LOG_ERROR("Write error: %d\n", result);
        }

        // Give the buffer back to io_uring, so it can be re-used
        recycle_buffer(buf_ring_, io_buffers_base_addr_, buffer_idx);
    }


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

    void add_accept()
    {
        io_uring_sqe *sqe = get_sqe();
        sqe->user_data = set_context(ContextType::Accept, /* client_fd */ -1, /* buffer_idx */ 0u);
        io_uring_prep_multishot_accept_direct(sqe, sockfd_idx, client_addr_, client_len_, 0);
    }

    void add_close(int client_fd)
    {
        io_uring_sqe *sqe = get_sqe();
        sqe->user_data = set_context(ContextType::Close, client_fd, /* buffer_idx */ 0u);
        io_uring_sqe_set_flags(sqe, IOSQE_CQE_SKIP_SUCCESS);
        io_uring_prep_close(sqe, client_fd);
    }

    void UringEchoServer::add_recv(int client_fd)
    {
        io_uring_sqe* sqe = get_sqe();
        set_context(sqe, ContextType::Read, client_fd, /* buffer_idx */ 0u);
        io_uring_prep_recv_multishot(sqe, client_fd, nullptr, 0, 0);
        sqe->flags |= IOSQE_BUFFER_SELECT;
        sqe->buf_group = BUFFER_GROUP_ID;
    }



    void add_recv(int client_fd)
    {
        io_uring_sqe *sqe = get_sqe();
        sqe->user_data = set_context(ContextType::Close, client_fd, /* buffer_idx */ 0u);

        sqe->flags |= IOSQE_FIXED_FILE;
        sqe->flags |= IOSQE_BUFFER_SELECT; // necessary for multishot
        sqe->buf_group = BUFFER_GROUP_ID;

        // this is so you know that later on (cqe->user_data < BUFFERS) woukd be false, hence it would go to recv
        //io_uring_sqe_set_data64(sqe, BUFFERS + 1);

        io_uring_prep_recv_multishot(sqe, client_fd, nullptr, 0, 0);
    }

    void add_send(int client_fd, const void* data, unsigned length, uint16_t buffer_idx)
    {
        io_uring_sqe *sqe = get_sqe();

    }
    void UringEchoServer::add_write(int client_fd, const void* data, unsigned length, uint16_t buffer_idx) {
        io_uring_sqe* sqe = get_sqe();
        set_context(sqe, ContextType::Write, client_fd, buffer_idx);
        io_uring_prep_write(sqe, client_fd, data, length, 0);
    }


};

