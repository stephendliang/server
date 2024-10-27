#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>

#define PORT 8080          // Port number to listen on
#define BACKLOG 128        // Number of pending connections queue will hold
#define MAX_EVENTS 64      // Maximum number of events to process at one time
#define BUFFER_SIZE 1024   // Buffer size for reading data

volatile sig_atomic_t keep_running = 1;

// Signal handler to gracefully shutdown the server
void handle_sigint(int sig) {
    keep_running = 0;
}

// Set a file descriptor to non-blocking mode
int set_nonblocking(int fd) {
    int flags;
    
    flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        perror("fcntl F_GETFL");
        return -1;
    }
    
    flags |= O_NONBLOCK;
    if (fcntl(fd, F_SETFL, flags) == -1) {
        perror("fcntl F_SETFL O_NONBLOCK");
        return -1;
    }
    
    return 0;
}

int main() {
    int listen_fd, conn_fd, kq;
    struct sockaddr_in server_addr;
    struct kevent change_event;
    struct kevent events[MAX_EVENTS];
    int nev, i;
    
    // Register signal handler for graceful shutdown
    struct sigaction sa;
    sa.sa_handler = handle_sigint;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }

    // Create a TCP socket
    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Allow reuse of address and port
    int opt = 1;
    if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
        perror("setsockopt SO_REUSEADDR");
        close(listen_fd);
        exit(EXIT_FAILURE);
    }

    // Set the socket to non-blocking mode
    if (set_nonblocking(listen_fd) == -1) {
        close(listen_fd);
        exit(EXIT_FAILURE);
    }

    // Bind the socket to the specified port
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY; // Listen on all interfaces
    server_addr.sin_port = htons(PORT);

    if (bind(listen_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("bind");
        close(listen_fd);
        exit(EXIT_FAILURE);
    }

    // Start listening for incoming connections
    if (listen(listen_fd, BACKLOG) == -1) {
        perror("listen");
        close(listen_fd);
        exit(EXIT_FAILURE);
    }

    // Create a new kqueue
    kq = kqueue();
    if (kq == -1) {
        perror("kqueue");
        close(listen_fd);
        exit(EXIT_FAILURE);
    }

    // Initialize kevent structure to monitor the listening socket for read events
    EV_SET(&change_event, listen_fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, NULL);

    // Register the event with kqueue
    if (kevent(kq, &change_event, 1, NULL, 0, NULL) == -1) {
        perror("kevent register listen_fd");
        close(listen_fd);
        close(kq);
        exit(EXIT_FAILURE);
    }

    printf("Server is listening on port %d...\n", PORT);

    // Event loop
    while (keep_running) {
        // Wait for events
        nev = kevent(kq, NULL, 0, events, MAX_EVENTS, NULL);
        if (nev == -1) {
            if (errno == EINTR) {
                // Interrupted by signal, continue if still running
                continue;
            }
            perror("kevent wait");
            break;
        }

        for (i = 0; i < nev; i++) {
            struct kevent *current_event = &events[i];

            if (current_event->flags & EV_ERROR) {
                fprintf(stderr, "EV_ERROR: %s\n", strerror((int)current_event->data));
                continue;
            }

            if (current_event->ident == listen_fd) {
                // New incoming connection
                while (1) {
                    struct sockaddr_in client_addr;
                    socklen_t client_len = sizeof(client_addr);
                    conn_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &client_len);
                    if (conn_fd == -1) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) {
                            // No more incoming connections
                            break;
                        } else {
                            perror("accept");
                            break;
                        }
                    }

                    // Set the new socket to non-blocking mode
                    if (set_nonblocking(conn_fd) == -1) {
                        close(conn_fd);
                        continue;
                    }

                    // Register the new socket with kqueue to monitor for read events
                    EV_SET(&change_event, conn_fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, NULL);
                    if (kevent(kq, &change_event, 1, NULL, 0, NULL) == -1) {
                        perror("kevent register conn_fd");
                        close(conn_fd);
                        continue;
                    }

                    printf("Accepted new connection: fd %d\n", conn_fd);
                }
            } else {
                // Data available to read on a client socket
                char buffer[BUFFER_SIZE];
                ssize_t bytes_read;

                while (1) {
                    bytes_read = read(current_event->ident, buffer, sizeof(buffer));
                    if (bytes_read > 0) {
                        // Echo the data back to the client
                        ssize_t bytes_written = 0;
                        ssize_t total_written = 0;
                        while (total_written < bytes_read) {
                            bytes_written = write(current_event->ident, buffer + total_written, bytes_read - total_written);
                            if (bytes_written == -1) {
                                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                                    // Can't write now, try later
                                    break;
                                } else {
                                    perror("write");
                                    close(current_event->ident);
                                    // Remove from kqueue
                                    EV_SET(&change_event, current_event->ident, EVFILT_READ, EV_DELETE, 0, 0, NULL);
                                    kevent(kq, &change_event, 1, NULL, 0, NULL);
                                    break;
                                }
                            }
                            total_written += bytes_written;
                        }
                    } else if (bytes_read == 0) {
                        // Connection closed by client
                        printf("Connection closed: fd %d\n", current_event->ident);
                        close(current_event->ident);
                        // Remove from kqueue
                        EV_SET(&change_event, current_event->ident, EVFILT_READ, EV_DELETE, 0, 0, NULL);
                        kevent(kq, &change_event, 1, NULL, 0, NULL);
                        break;
                    } else {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) {
                            // No more data to read
                            break;
                        } else {
                            perror("read");
                            close(current_event->ident);
                            // Remove from kqueue
                            EV_SET(&change_event, current_event->ident, EVFILT_READ, EV_DELETE, 0, 0, NULL);
                            kevent(kq, &change_event, 1, NULL, 0, NULL);
                            break;
                        }
                    }
                }
            }
        }
    }

    printf("\nShutting down server...\n");

    // Clean up: close all file descriptors
    close(listen_fd);
    close(kq);

    return 0;
}
