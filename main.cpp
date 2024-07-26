#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>

#include "helper.h"
#include "sort_ckks.h"

using namespace lbcrypto;
using namespace std;


int main() {



    // Generate Crypto Context
    auto cc = get_context_ckks();
    // Key generation
    auto keys = cc->KeyGen();
    // Serialize into binary files
    std::cout << "GENERATING KEYS!" << std::endl;
    serialize_keys(cc);


    // ------------------- Dummy Input for local testing -------------------
    // Input Vector
    vector<double> input = {3.0, 1.0, 4.0, 1.5, 5.0, 9.0, 2.0, 6.0};

    vector<Plaintext> plaintexts;
    vector<Ciphertext<DCRTPoly>> ciphertexts;

    ciphertexts = encrypt_and_serialize_plaintext(cc, keys, plaintexts, input);
    
    std::cout << "KEY GENERATION DONE!" << std::endl;
    // ------------------- Dummy Input for local testing -------------------




    SortCKKS sortCKKS(ccLocation, pubKeyLocation, multKeyLocation, rotKeyLocation, inputLocation,
                             outputLocation);
              
    sortCKKS.eval();
    sortCKKS.deserializeOutput();

    return 0;
}
