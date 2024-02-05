// coffin.cpp : This file contains the 'main' function. Program execution begins and ends there.
//


#pragma warning(disable : 4996) // need to refactor the hash functions

#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
//#include <string>
#include "hashes.h"

int parse_file(std::string filepath) {

    std::string signature;
    std::ifstream file_in;

    file_in.open(filepath, std::ios::in | std::ios::binary);

    file_in.seekg(0, std::ios::end); //move to end of file
    int file_length = file_in.tellg(); //getfile length 

    
    file_in.seekg(0, std::ios::beg); //return to the beginning
    file_in.read((char*)&signature, 2);
    if (signature == "MZ") {
        //windows PE signature
    } else {
        //not PE file or corupted
    };
    
    file_in.close();

    return 0;
}


int main()

{
    // step 1. get the md5 and sha256 hashes of the file
    char the_sha256_hash[65];
    char the_md5_hash[33];
    hash_sha256_file("coffin.cpp", the_sha256_hash);
    hash_md5_file("coffin.cpp", the_md5_hash);
    std::cout << hash_sha256_string("Terminal Root") << '\n';
    std::cout << hash_md5_string("Terminal Root") << '\n';
    std::cout << the_sha256_hash << '\n';
    std::cout << the_md5_hash << std::endl;
    return 0;
}


