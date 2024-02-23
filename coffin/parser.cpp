#include <iostream>
//#include <iomanip>
#include <sstream>
#include <fstream>

using std::string; using std::cout; using std::cin; using std::ios; using std::endl;

int parse_file(std::string filepath) {

    string signature;
    std::ifstream file_in;

    file_in.open(filepath, ios::in | ios::binary);

    file_in.seekg(0, ios::end); //move to end of file
    int file_length = file_in.tellg(); //getfile length 


    file_in.seekg(0, ios::beg); //return to the beginning
    file_in.read((char*)&signature, 2);
    if (signature == "MZ") {
        //windows PE signature
    }
    else {
        //not PE file or corupted
    };

    file_in.close();

    return 0;
}
