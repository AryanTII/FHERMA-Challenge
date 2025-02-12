#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>

#include "sort_ckks.h"

using namespace lbcrypto;
using namespace std;


int main(int argc, char *argv[]) {
    std::string pubKeyLocation;
    std::string multKeyLocation;
    std::string rotKeyLocation;
    std::string ccLocation;
    std::string inputLocation;
    std::string outputLocation;

    std::this_thread::sleep_for(std::chrono::seconds(2));
    for (int i = 1; i < argc; i += 2) {
        std::string arg = argv[i];
        if (arg == "--key_public") {
            pubKeyLocation = argv[i + 1];
        } else if (arg == "--key_mult") {
            multKeyLocation = argv[i + 1];
        } else if (arg == "--key_rot") {
            rotKeyLocation = argv[i + 1];
        } else if (arg == "--cc") {
            ccLocation = argv[i + 1];
        } else if (arg == "--array") {
            inputLocation = argv[i + 1];
        } else if (arg == "--output") {
            outputLocation = argv[i + 1];
        }
    }


    SortCKKS sortCKKS(ccLocation, pubKeyLocation, multKeyLocation, rotKeyLocation, inputLocation,
                             outputLocation);
              
    sortCKKS.eval();
    sortCKKS.deserializeOutput();

    return 0;
}
