#include "server.hh"

int main()
{
    uring_server srv;

    srv.setup_params();
    srv.evloop();

    return 0;
}
