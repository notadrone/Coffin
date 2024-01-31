// coffin.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
//https://www.openssl.org/docs/manmaster/man3/SHA256.html
//https://www.openssl.org/docs/manmaster/man3/EVP_DigestInit_ex.html

#pragma warning(disable : 4996) // need to refactor the hash functions

#include <iostream>
#include <iomanip>
#include <sstream>
#include <openssl/sha.h>

std::string sha256(const std::string str) {
    unsigned char hash[SHA256_DIGEST_LENGTH];

    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);

    std::stringstream ss;

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str();
}

void sha256_hash_string(unsigned char hash[SHA256_DIGEST_LENGTH], char outputBuffer[65])
{
    int i = 0;

    for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }

    outputBuffer[64] = 0;
}

int sha256_file(char* path, char outputBuffer[65])
{
    FILE* file = fopen(path, "rb");
    if (!file) return -534;

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    const int bufSize = 32768;
    unsigned char* buffer = (unsigned char*) malloc(bufSize);
    int bytesRead = 0;
    if (!buffer) return ENOMEM;
    while ((bytesRead = fread(buffer, 1, bufSize, file)))
    {
        SHA256_Update(&sha256, buffer, bytesRead);
    }
    SHA256_Final(hash, &sha256);

    sha256_hash_string(hash, outputBuffer);
    fclose(file);
    free(buffer);
    return 0;
}
int main()
{
    std::cout << sha256("Terminal Root") << '\n';
    return 0;
}

//SHA256_CTX sha256;
//SHA256_Init(&sha256);
//FILE* f = ...; // pretend it's valid and gets cleaned up
//while (true)
//{
//    unsigned char buf[4096];
//    // in case we get less bytes back than we request
//    size_t actual_len = read_from_file(f, buf, sizeof(buf));
//    SHA256_Update(&sha256, buf, actual_len);
//}
//SHA256_Final(hash, &sha256);
