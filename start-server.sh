#! /bin/bash

openssl s_server -cipher AES128-SHA256 -psk_identity TestIdentity -psk_hint TestIdentityHint -psk "4E635266556A586E3272357538782F41" -tls1_2 -key key.pem -cert cert.pem -accept 127.0.0.1:2000
