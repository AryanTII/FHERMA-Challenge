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

class LookUp {
    CryptoContext<DCRTPoly> m_cc;
    PublicKey<DCRTPoly> m_PublicKey;
    Ciphertext<DCRTPoly> m_InputC;
    Ciphertext<DCRTPoly> m_IndexC;
    Ciphertext<DCRTPoly> m_OutputC;
    string m_PubKeyLocation;
    string m_MultKeyLocation;
    string m_RotKeyLocation;
    string m_CCLocation;
    string m_InputLocation;
    string m_IndexLocation;
    string m_OutputLocation;
    usint array_limit;
    // Creating evalKeyMap and evalMultKey
    // map<usint, EvalKey<DCRTPoly>> evalKeyMap;
    // EvalKey<DCRTPoly> evalMultKey;

public:
    LookUp(string ccLocation, string pubKeyLocation, string multKeyLocation,
                string rotKeyLocation, string inputLocation, string indexLocation, string outputLocation);

    void initCC();
    void eval();
    void deserializeOutput();
};