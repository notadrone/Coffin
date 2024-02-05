#pragma once

#include <iostream>
#include <openssl/sha.h>
#include <openssl/md5.h>

std::string hash_sha256_string(const std::string str);

void sha256_hex_string(unsigned char hash[SHA256_DIGEST_LENGTH], char outputBuffer[65]);

int hash_sha256_file(const char* path, char outputBuffer[65]);

std::string hash_md5_string(const std::string str);

int hash_md5_file(const char* path, char outputBuffer[65]);

void md5_hex_string(unsigned char hash[MD5_DIGEST_LENGTH], char outputBuffer[33]);