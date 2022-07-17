#include "open_ssl_client.h"

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <algorithm>
#include <iostream>
#include <string>
#include <string.h>

namespace {

std::string test_psk_identity_hint = "TestIdentityHint";
std::string test_psk_identity = "TestIdentity";
std::string test_psk = "4E635266556A586E3272357538782F41";

unsigned int psk_client_cb(SSL* ssl, const char* hint, char* identity,
                  unsigned int max_identity_len, unsigned char* psk,
                  unsigned int max_psk_len) {
  size_t const identity_len = std::min(test_psk_identity.size(), static_cast<size_t>(max_identity_len));
  strncpy(identity, test_psk_identity.c_str(), identity_len);

  size_t const psk_len = std::min(test_psk.size(), static_cast<size_t>(max_psk_len));
  memcpy(psk, test_psk.c_str(), psk_len);

  return psk_len;
}

} // namespace

namespace open_ssl {

OpenSslClient::OpenSslClient() noexcept :
    ssl_{nullptr},
    ssl_ctx_{nullptr},
    is_connected_{false} {
  InitializeOpenSsl();
  InitializeContext();
}

OpenSslClient::~OpenSslClient() noexcept {
  if (ssl_) {
    SSL_shutdown(ssl_);
    SSL_free(ssl_);
  }

  SSL_CTX_free(ssl_ctx_);
}

bool OpenSslClient::SetSocketFd(int socket_fd) noexcept {
  ssl_ = SSL_new(ssl_ctx_);

  SSL_set_psk_client_callback(ssl_, psk_client_cb);

  int const res = SSL_set_fd(ssl_, socket_fd);

  if (1 != res) {
    SSL_get_error(ssl_, res);
    ERR_print_errors_fp(stderr);
  }

  return static_cast<bool>(res);
}

bool OpenSslClient::PerformHandshake() noexcept {
  if (is_connected_)
    return true;

  int const res = SSL_connect(ssl_);
  if (1 != res) {
    SSL_get_error(ssl_, res);
    ERR_print_errors_fp(stderr);
  }

  is_connected_ = static_cast<bool>(res);

  return is_connected_;
}

int OpenSslClient::Write(char const* buffer, size_t const len) noexcept {
  return SSL_write(ssl_, buffer, len);
}

std::vector<uint8_t> OpenSslClient::Read() {
  char buffer[1024];

  std::vector<uint8_t> output;
  size_t bytes_read = SSL_read(ssl_, buffer, sizeof(buffer));
  std::copy(buffer, buffer + bytes_read, std::back_inserter(output));

  return output;
}

void OpenSslClient::InitializeOpenSsl() noexcept {
  // Initialize libcrypto and libssl.
  SSL_library_init();

  // Load error strings from libcrypto and libssl.
  SSL_load_error_strings();
}

void OpenSslClient::InitializeContext() noexcept {
  // Initialize TLS 1.2.
  SSL_METHOD const * method = TLS_client_method();
  if (!method) {
    std::cerr << "Failed to initialize TLS method.";
    std::exit(1);
  }

  // Initialize the ssl context.
  ssl_ctx_ = SSL_CTX_new(method);
  if (!ssl_ctx_) {
    std::cerr << "Failed to initialize SSL context.";
    std::exit(1);
  }

	if(0 == SSL_CTX_set_cipher_list(ssl_ctx_, "AES128-SHA256")) {
    std::cerr << "Failed to set cipher\n";
    ERR_print_errors_fp(stderr);
    std::exit(1);
  }
}

} // namespace open_ssl
