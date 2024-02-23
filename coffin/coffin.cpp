// coffin.cpp : This file contains the 'main' function. Program execution begins and ends there.
//


#pragma warning(disable : 4996) // need to refactor the hash functions

#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <string>
#include "hashes.h"

using std::string; using std::cout; using std::cin; using std::ios; using std::endl;



int main()

{
    // step 1. get the md5 and sha256 hashes of the file
    char the_sha256_hash[65];
    //string the_file_hash;
    string the_file_hash;
    string the_file_hash2;
    //char the_md5_hash[33];
    hash_sha256_file("coffin.cpp", the_sha256_hash);
    evp_sha256_file("coffin.cpp", the_file_hash2);
    //hash_md5_file("coffin.cpp", the_md5_hash);
    //cout << hash_sha256_string("Hello World!") << '\n';
    //cout << hash_md5_string("Terminal Root") << '\n';
    cout << the_sha256_hash << '\n';
    cout << the_file_hash2 << '\n';
    cout << the_file_hash << '\n';
    //cout << the_md5_hash << endl;
    string thestring = "Hello World!";
    //cout << evp_sha256_string (thestring) << endl;
    return 0;
}


