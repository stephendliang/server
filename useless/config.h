#pragma once

#include <netinet/in.h>
#include <a3/str.h>

typedef struct Config {
    A3CString web_root;
    int       log_level;
    in_port_t listen_port;
} Config;

extern Config CONFIG;
