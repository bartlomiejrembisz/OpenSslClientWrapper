#include <iostream>
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <strings.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#include "open_ssl_client.h"

int CreateTcpSocket(std::string const &address, uint16_t const port) {
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    std::cerr << "Failed to create socket\n";
    return -1;
  }

  std::cout << "Connecting to " << address << ":" << port << "\n";
  
  struct sockaddr_in server_addr;
  bzero(&server_addr, sizeof(server_addr));

  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = inet_addr(address.c_str());
  server_addr.sin_port = htons(port);

  int res = connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr));
  if (0 > res) {
    std::cerr << "Failed to connect to address.\n";
    std::cerr << strerror(errno) << "\n";
    return -1;
  }
  
  return sockfd;
}

int main(int, char**) {
  int socket = CreateTcpSocket("127.0.0.1", 2000);
  if (-1 == socket)
    exit(1);
  open_ssl::OpenSslClient open_ssl_client;
  if(!open_ssl_client.SetSocketFd(socket)) {
    std::cerr << "Failed to set socket.\n";
    std::exit(1);
  }

  if(!open_ssl_client.PerformHandshake()) {
    std::cerr << "Failed to perform handshake.\n";
    std::exit(1);
  }

  std::cin.get();
  open_ssl_client.Write("test", sizeof("test"));
  std::vector<uint8_t> data = open_ssl_client.Read();
  std::cout << std::string(data.begin(), data.end()) << "\n";

  close(socket);
}

