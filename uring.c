static struct io_uring ring;

void setup_params()
{
    struct io_uring_params params;
    memset(&params, 0, sizeof(params));

    //params.flags |= IORING_SETUP_SQPOLL;
    params.flags = (IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN);


    if (io_uring_queue_init_params(MAX_MESSAGE_LEN, &ring, &params) < 0) {
        perror("io_uring_init_failed...\n");
        exit(1);
    }

    // check if IORING_FEAT_FAST_POLL is supported
    if (!(params.features & IORING_FEAT_FAST_POLL)) {
        printf("IORING_FEAT_FAST_POLL not available in the kernel, quiting...\n");
        exit(0);
    }

    puts("params2");

    // check if buffer selection is supported
    struct io_uring_probe *probe;
    probe = io_uring_get_probe_ring(&ring);
    if (!probe || !io_uring_opcode_supported(probe, IORING_OP_PROVIDE_BUFFERS)) {
        printf("Buffer select not supported, skipping...\n");
        exit(0);
    }
}
