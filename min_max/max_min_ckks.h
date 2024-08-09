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

class MaxMinCKKS {
    CryptoContext<DCRTPoly> m_cc;
    PublicKey<DCRTPoly> m_PublicKey;
    Ciphertext<DCRTPoly> m_InputC;
    Ciphertext<DCRTPoly> m_OutputC;
    Plaintext m_MaskLookup;
    Plaintext m_Half;
    Plaintext m_One;
    string m_PubKeyLocation;
    string m_MultKeyLocation;
    string m_RotKeyLocation;
    string m_CCLocation;
    string m_InputLocation;
    string m_OutputLocation;
    int array_limit;
    double Norm_Value;

public:
    MaxMinCKKS(string ccLocation, string pubKeyLocation, string multKeyLocation,
            string rotKeyLocation, string inputLocation, string outputLocation);

    void initCC();
    void eval();
    void deserializeOutput();

    Ciphertext<DCRTPoly> sign(Ciphertext<DCRTPoly> m_InputC);
    Ciphertext<DCRTPoly> cond_swap(Ciphertext<DCRTPoly> m_InputC, bool is_even);
    Ciphertext<DCRTPoly> compare_div(const Ciphertext<DCRTPoly>& a, const Ciphertext<DCRTPoly>& b, double epsilon);


    Ciphertext<DCRTPoly> compare(Ciphertext<DCRTPoly> m_InputA, Ciphertext<DCRTPoly> m_InputB);
    Ciphertext<DCRTPoly> round(Ciphertext<DCRTPoly> m_InputC, int len_comparison_vector, bool is_max);


};