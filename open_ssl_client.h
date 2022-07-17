#ifndef OPEN_SSL_CLIENT_H_
#define OPEN_SSL_CLIENT_H_

#include <openssl/conf.h>

#include <vector>

class OpenSslClient {
 public:
  OpenSslClient() noexcept;

  ~OpenSslClient() noexcept;

  bool SetSocketFd(int socket_fd) noexcept;

  bool PerformHandshake() noexcept;

  int Write(char const* buffer, size_t const len) noexcept;

  std::vector<uint8_t> Read();

 private:
  void InitializeOpenSsl() noexcept;

  void InitializeContext() noexcept;

  SSL* ssl_;
  SSL_CTX* ssl_ctx_;
  bool is_connected_;
};

} // namespace

#endif // OPEN_SSL_CLIENT_H_