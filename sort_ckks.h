#include "openfhe.h"
#include "stdio.h"
#include <cmath>
#include <string>
#include <vector>

// header files needed for serialization
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"

using namespace lbcrypto;
using namespace std;

class SortCKKS {
    CryptoContext<DCRTPoly> m_cc;
    PublicKey<DCRTPoly> m_PublicKey;
    Ciphertext<DCRTPoly> m_InputC;
    Ciphertext<DCRTPoly> m_OutputC;
    Plaintext m_MaskOdd;
    Plaintext m_MaskEven;
    string m_PubKeyLocation;
    string m_MultKeyLocation;
    string m_RotKeyLocation;
    string m_CCLocation;
    string m_InputLocation;
    string m_OutputLocation;
    int array_limit;

public:
    SortCKKS(string ccLocation, string pubKeyLocation, string multKeyLocation,
                string rotKeyLocation, string inputLocation, string outputLocation);

    void initCC();
    void eval();
    void deserializeOutput();

    Ciphertext<DCRTPoly> compare(Ciphertext<DCRTPoly> m_InputA, Ciphertext<DCRTPoly> m_InputB);

};