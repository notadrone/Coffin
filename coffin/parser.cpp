#include <iostream>
//#include <iomanip>
#include <sstream>
#include <fstream>

using std::string; using std::cout; using std::cin; using std::ios; using std::endl;

int parse_file(std::string filepath) {

    string signature;
    std::ifstream file_in;
    char * pString;

    pString = &signature[0];

    file_in.open(filepath, ios::in | ios::binary | ios::ate);
    cout <<"\nOpening File\n";
    file_in.seekg(0, ios::end);                     //move to end of file
    std::streampos file_length = file_in.tellg();   //getfile length 
    file_in.seekg(0, ios::beg);                     //return to the beginning
    //file_in.read((char*)&signature, 2);
    file_in.read(pString, 2);

    file_in.close();
    cout << "Close file\n";

    if (strcmp (signature.c_str(), "MZ") == 0) {    //this is a cludge and needs attention
        //windows PE signature
        std::cout << "is a PE file: " << signature.c_str();
    }
    else {
        //not PE file or corupted
        std::cout << "Not a PE File: " << signature.c_str();
    };

    return 0;
}
