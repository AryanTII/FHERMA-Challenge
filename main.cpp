#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>

#include "helper.h"

using namespace lbcrypto;
using namespace std;

Ciphertext<DCRTPoly> HomomorphicCompare(CryptoContext<DCRTPoly> cc, Ciphertext<DCRTPoly> a, Ciphertext<DCRTPoly> b) {
    return a;
}

void HomomorphicSwap(CryptoContext<DCRTPoly> cc, Ciphertext<DCRTPoly>& a, Ciphertext<DCRTPoly>& b) {
    auto temp = a;
    a = HomomorphicCompare(cc, a, b);
    b = cc->EvalSub(temp, a);
}

void AKSSort(CryptoContext<DCRTPoly> cc, vector<Ciphertext<DCRTPoly>>& data) {
    size_t n = data.size();
    for (size_t width = 1; width < n; width *= 2) {
        for (size_t i = 0; i < n; i += 2 * width) {
            for (size_t j = i; j < i + width && j + width < n; ++j) {
                HomomorphicSwap(cc, data[j], data[j + width]);
            }
        }
    }
}

int main() {
    // Generate Crypto Context
    auto cc = get_context_ckks();
    // Key generation
    auto keys = cc->KeyGen();
    // Serialize into binary files
    std::cout << "GENERATING KEYS!" << std::endl;
    serialize_keys(cc);


    // Input Vector
    vector<double> input = {3.0, 1.0, 4.0, 1.5, 5.0, 9.0, 2.0, 6.0};

    vector<Plaintext> plaintexts;
    vector<Ciphertext<DCRTPoly>> ciphertexts;

    ciphertexts = encrypt_and_serialize_plaintext(cc, keys, plaintexts, input);
    
    std::cout << "KEY GENERATION DONE!" << std::endl;

    SortCKKS SortCKKS(ccLocation, pubKeyLocation, multKeyLocation, rotKeyLocation, inputLocation,
                             outputLocation);
                             
    // Sort using AKS network
    // AKSSort(cc, ciphertexts);

    // Decrypt and print the sorted result
    vector<double> sortedResult;
    for (auto &cipher : ciphertexts) {
        Plaintext p;
        cc->Decrypt(keys.secretKey, cipher, &p);
        sortedResult.push_back(p->GetRealPackedValue()[0]);
    }

    cout << "Sorted Result:" << endl;
    for (const auto &val : sortedResult) {
        cout << val << " ";
    }
    cout << endl;

    return 0;
}
