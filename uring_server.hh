#pragma once

#include <cstdlib>
#include <liburing.h>
#include <netinet/in.h>

#define CQE_CLASSIC_LOOP 0
#define CQE_LIBURING_LOOP 1

#define CQE_LOOP_STYLE CQE_CLASSIC_LOOP


#define CQE_HANDLER_FUNCTION_TABLE 0
#define CQE_HANDLER_IF_CHAIN 1

#define CQE_HANDLER_STYLE CQE_HANDLER_FUNCTION_TABLE



#define USE_ZEROCOPY 0

#define USE_REGISTERED_FD



#define flag_is_set(cqe, flag) (cqe->flags & flag)

enum class URING_OP : uint8_t
{
    ACCEPT,
    RECV,
    SEND,
    CLOSE,
};

enum class output_type : uint8_t
{
    server = 0,
    client,
    database
};

union user_data_t
{
    uint64_t value;

    struct {
        int64_t client_fd : 32;
        int64_t type : 16;
        int64_t buffer_idx : 16;
    } bitfield;

    inline user_data_t() {}

    inline user_data_t(int32_t c, URING_OP t, int16_t b) {
        bitfield.client_fd = c;
        bitfield.type = int16_t(t);
        bitfield.buffer_idx = b;
    }
};

inline uint64_t userdata2value(int32_t c, URING_OP t, int16_t b)
{
    user_data_t ud(c, t, b);
    return ud.value;
}


// Min number of entries to wait for in the event loop
#define NUM_WAIT_ENTRIES 1

// The maximum number of entries to retrieve in a single loop iteration
#define CQE_BATCH_SIZE 256

// The size of the SQ. By default, the CQ ring will be twice this number
#define NUM_SUBMISSION_QUEUE_ENTRIES 4096

// The size of each pre-allocated IO buffer. Power-of-2.
#define IO_BUFFER_SIZE 2048

// The number of IO buffers to pre-allocate
#define NUM_IO_BUFFERS 4096

#define BUFFER_GROUP_ID 1

#define NUM_FILES_REGISTERED 8192



class uring_server
{
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
    uring_server(uint16_t port);

    ~uring_server();

    int process_rate_limit();

    int setup_buffers(int group_id);

    void evloop();

    void handle_accept(io_uring_cqe* cqe, int client_fd_idx, uint16_t placeholder);

    void handle_recv(io_uring_cqe* cqe, int client_fd_idx, uint16_t placeholder);

    void handle_send(io_uring_cqe* cqe, int client_fd_idx, uint16_t buffer_idx);

    io_uring_sqe* get_sqe();

    inline void add_accept()
    {
        io_uring_sqe *sqe = get_sqe();
        io_uring_sqe_set_data64(sqe, userdata2value(-1, URING_OP::ACCEPT, 0));

        io_uring_prep_multishot_accept_direct(sqe, listening_socket_, (sockaddr*)&client_addr_, &client_addr_len_, 0);
    }

    inline void add_close(int client_fd_idx)
    {
        io_uring_sqe *sqe = get_sqe();
        io_uring_sqe_set_data64(sqe, userdata2value(client_fd_idx, URING_OP::CLOSE, 0));

        io_uring_prep_close(sqe, client_fd_idx);
        io_uring_sqe_set_flags(sqe, IOSQE_CQE_SKIP_SUCCESS);
    }

    inline void add_recv(int client_fd_idx)
    {
        io_uring_sqe* sqe = get_sqe();
        io_uring_sqe_set_data64(sqe, userdata2value(client_fd_idx, URING_OP::RECV, 0));

        // len must be 0
        io_uring_prep_recv_multishot(sqe, client_fd_idx, nullptr, 0, 0);
        io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE | IOSQE_BUFFER_SELECT);
        sqe->buf_group = BUFFER_GROUP_ID;
    }

    inline void add_send(int client_fd, const void* data, unsigned length, uint16_t buffer_idx)
    {
        /*
       void io_uring_prep_send_zc(struct io_uring_sqe *sqe,
                                  int sockfd,
                                  const void *buf,
                                  size_t len,
                                  int flags,
                                  unsigned zc_flags);

       void io_uring_prep_send_zc_fixed(struct io_uring_sqe *sqe,
                                        int sockfd,
                                        const void *buf,
                                        size_t len,
                                        int flags,
                                        unsigned zc_flags);
                                        unsigned buf_index);


       void io_uring_prep_send(struct io_uring_sqe *sqe,
                               int sockfd,
                               const void *buf,
                               size_t len,
                               int flags);
        */
        io_uring_sqe* sqe = get_sqe();
        io_uring_sqe_set_data64(sqe, userdata2value(client_fd_idx, URING_OP::SEND, buffer_idx));

        io_uring_prep_send(sqe, client_fd, data, length, 0);
#if USE_ZEROCOPY
        //io_uring_prep_send_zc_fixed(sqe, client_fd_idx, data, length, 0);
#endif
    }
};
