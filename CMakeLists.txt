cmake_minimum_required(VERSION 3.0.0)
project(OpenSslClient VERSION 0.1.0)

set(OPENSSL_USE_STATIC_LIBS TRUE)

add_executable(OpenSslClient open_ssl_client.cpp main.cpp)
target_link_libraries(OpenSslClient ssl crypto)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
