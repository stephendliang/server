#pragma once

#include <liburing.h>
#include <netinet/in.h>

#define CQE_CLASSIC_LOOP 0
#define CQE_LIBURING_LOOP 1

#define CQE_LOOP_STYLE CQE_CLASSIC_LOOP


#define CQE_HANDLER_FUNCTION_TABLE 0
#define CQE_HANDLER_IF_CHAIN 1

#define CQE_HANDLER_STYLE CQE_HANDLER_FUNCTION_TABLE

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

struct user_data_t
{
    int64_t client_fd : 32;
    int64_t type : 16;
    int64_t buffer_idx : 16;
};

// Context layout (8-bytes)
// | 4-bytes - client_fd | 1-byte - type | 2-bytes - buffer index | 1-byte not used
static void set_context(io_uring_sqe* sqe, ContextType type, int32_t client_fd, uint16_t buffer_idx)
{
    // Make sure we can fit our context in io_uring_sqe::user_data/io_uring_cqe::user_data
    &sqe->user_data = user_data_t{client_fd, type, buffer_idx};
}

class uring_server
{
/*
    unsigned char *buffer_base;
    struct msghdr msg;
    int buf_shift;
    int af;
    bool verbose;
    struct sendmsg_ctx send[BUFFERS];
    size_t buf_ring_size;


    // Min number of entries to wait for in the event loop
    static constexpr unsigned NUM_WAIT_ENTRIES = 1;
    // The maximum number of entries to retrieve in a single loop iteration
    static constexpr unsigned CQE_BATCH_SIZE = 256;
    // The size of the SQ. By default, the CQ ring will be twice this number
    static constexpr unsigned NUM_SUBMISSION_QUEUE_ENTRIES = 2048;
    // The size of each pre-allocated IO buffer. Power-of-2.
    static constexpr unsigned IO_BUFFER_SIZE = 2048;
    // The number of IO buffers to pre-allocate
    static constexpr uint16_t NUM_IO_BUFFERS = 4096;
*/

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
    uring_server();

    ~uring_server();

    int process_rate_limit();

    int setup_buffers(int group_id);

    void evloop();

    void handle_accept(io_uring_cqe* cqe, uint16_t buffer_idx);

    void handle_recv(io_uring_cqe* cqe, uint16_t buffer_idx);

    void handle_send(io_uring_cqe* cqe, uint16_t buffer_idx);

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

    inline void add_accept(int sockfd_idx)
    {
        io_uring_sqe *sqe = get_sqe();
        io_uring_sqe_set_data64(sqe, user_data_t(-1, URING_OP::ACCEPT, 0));

        io_uring_prep_multishot_accept_direct(sqe, sockfd_idx, client_addr_, client_len_, 0);
    }

    inline void add_close(int client_fd)
    {
        io_uring_sqe *sqe = get_sqe();
        io_uring_sqe_set_data64(sqe, set_context(client_fd, URING_OP::CLOSE, 0));

        io_uring_prep_close(sqe, client_fd);
        io_uring_sqe_set_flags(sqe, IOSQE_CQE_SKIP_SUCCESS);
    }

    inline void add_recv(int client_fd_idx)
    {
        io_uring_sqe* sqe = get_sqe();
        io_uring_sqe_set_data64(sqe, set_context(client_fd_idx, URING_OP::RECV, 0));

        // len must be 0
        io_uring_prep_recv_multishot(sqe, client_fd_idx, nullptr, 0, 0);
        io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE | IOSQE_BUFFER_SELECT);
        sqe->buf_group = BUFFER_GROUP_ID;
    }

    inline void add_send(int client_fd, const void* data, unsigned length, uint16_t buffer_idx)
    {
        io_uring_sqe* sqe = get_sqe();
        io_uring_sqe_set_data64(sqe, set_context(client_fd, URING_OP::SEND, buffer_idx));

        io_uring_prep_send_zc_fixed(sqe, client_fd, data, length, 0);
    }
};
