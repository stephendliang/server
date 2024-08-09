
int get_udp_socket(int portno)
{
  struct sockaddr_in serv_addr;

  // setup socket
  int sock_listen_fd = socket(AF_INET, SOCK_DGRAM, 0);
  const int val = 1;
  setsockopt(sock_listen_fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));

  if (setsockopt(sock_listen_fd, SOL_SOCKET, SO_ZEROCOPY, &val, sizeof(val)))
    perror("setsockopt zerocopy");

  memset(&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(portno);
  serv_addr.sin_addr.s_addr = INADDR_ANY;

  // bind and listen
  if (bind(sock_listen_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
    perror("Error binding socket...\n");
    exit(1);
  }

  if (listen(sock_listen_fd, BACKLOG) < 0) {
    perror("Error listening on socket...\n");
    exit(1);
  }

  return sock_listen_fd;
}
