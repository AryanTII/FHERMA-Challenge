#include "openfhe.h"
#include "stdio.h"
#include <cmath>
#include <string>
#include <vector>

using namespace lbcrypto;
using namespace std;

class SortCKKS {
    CryptoContext<DCRTPoly> m_cc;
    PublicKey<DCRTPoly> m_PublicKey;
    Ciphertext<DCRTPoly> m_InputC;
    Ciphertext<DCRTPoly> m_OutputC;
    string m_PubKeyLocation;
    string m_MultKeyLocation;
    string m_RotKeyLocation;
    string m_CCLocation;
    string m_InputLocation;
    string m_OutputLocation;

public:
    SortCKKS(string ccLocation, string pubKeyLocation, string multKeyLocation,
                string rotKeyLocation, string inputLocation, string outputLocation);

    void initCC();
    void eval();
    void deserializeOutput();
};