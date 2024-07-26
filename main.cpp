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
    uint32_t batchSize = 8;
    // Input Vector
    vector<double> input = {3.0, 1.0, 4.0, 1.5, 5.0, 9.0, 2.0, 6.0};

    Plaintext plaintext = cc->MakeCKKSPackedPlaintext(input);
    std::cout << "Input vector: " << plaintext << std::endl;

    Ciphertext<DCRTPoly> ciphertext = cc->Encrypt(keys.publicKey, plaintext);

    // // Serialize input
    if (!Serial::SerializeToFile(inputLocation, ciphertext, SerType::BINARY)) {
        std::cerr << "Error serializing input file" << std::endl;
        std::exit(1);
    }
    
    std::cout << "KEY GENERATION DONE!" << std::endl;
    // ------------------- Dummy Input for local testing -------------------




    SortCKKS sortCKKS(ccLocation, pubKeyLocation, multKeyLocation, rotKeyLocation, inputLocation,
                             outputLocation);
              
    sortCKKS.eval();
    sortCKKS.deserializeOutput();

    sortCKKS.viewInputOutput(cc, keys, batchSize);

    return 0;
}
