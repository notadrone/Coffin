//https://www.openssl.org/docs/manmaster/man3/SHA256.html
//https://www.openssl.org/docs/manmaster/man3/EVP_DigestInit_ex.html

#pragma warning(disable : 4996) // need to refactor the hash functions

#include <iostream>
#include <iomanip>
#include <sstream>
#include <openssl/sha.h>
#include <openssl/md5.h>

std::string hash_sha256_string(const std::string str) {
    /*
    calculates the SHA256 of a string
    
    input: a standard string object
     
    output: a string object containing the hexadecimal representation
    of the hash
    */
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

std::string hash_md5_string(const std::string str) {
    /*
    calculates the MD5 hash of a string

    input: a standard string object

    output: a string object containing the hexadecimal representation
    of the hash
    */
    unsigned char hash[MD5_DIGEST_LENGTH];

    MD5_CTX the_context;
    MD5_Init(&the_context);
    MD5_Update(&the_context, str.c_str(), str.size());
    MD5_Final(hash, &the_context);

    std::stringstream ss;

    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str();
}

void sha256_hex_string(unsigned char hash[SHA256_DIGEST_LENGTH], char outputBuffer[65])
{
    int i = 0;

    for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }

    outputBuffer[64] = 0;
}

void md5_hex_string(unsigned char hash[MD5_DIGEST_LENGTH], char outputBuffer[33])
{
    int i = 0;

    for (i = 0; i < MD5_DIGEST_LENGTH; i++)
    {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }

    outputBuffer[32] = 0;
}

int hash_sha256_file(const char* path, char outputBuffer[65])
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX theContext;
    SHA256_Init(&theContext);

    const int buffer_size = 32768;
    unsigned char* buffer = (unsigned char*)malloc(buffer_size);
    if (!buffer) return ENOMEM;
    
    FILE* file = fopen(path, "rb");
    //!TODO - error handling find proper error number constants
    if (!file) return -534; //??? What error number is this ???

    int bytesRead = 0;
    while ((bytesRead = fread(buffer, 1, buffer_size, file)))
    {
        SHA256_Update(&theContext, buffer, bytesRead);
    }
    SHA256_Final(hash, &theContext);
    sha256_hex_string(hash, outputBuffer); //convert the binary hash into a hex string
    fclose(file);
    free(buffer); //there is a return path between this free and it's malloc
                    //fix for possible leaks??
    return 0;
}

int hash_md5_file(const char* path, char outputBuffer[65])
{
    unsigned char hash[MD5_DIGEST_LENGTH];
    MD5_CTX theContext;
    MD5_Init(&theContext);

    const int buffer_size = 32768;
    unsigned char* buffer = (unsigned char*)malloc(buffer_size);
    if (!buffer) return ENOMEM;

    FILE* file = fopen(path, "rb");
    //!TODO - error handling find proper error number constants
    if (!file) return -534; //??? What error number is this ???

    int bytesRead = 0;
    while ((bytesRead = fread(buffer, 1, buffer_size, file)))
    {
        MD5_Update(&theContext, buffer, bytesRead);
    }
    MD5_Final(hash, &theContext);
    md5_hex_string(hash, outputBuffer); //convert the binary hash into a hex string
    fclose(file);
    free(buffer); //there is a return path between this free and it's malloc
    //fix for possible leaks??
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