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

// Key location
static const string pubKeyLocation = "./key_pub.bin";
static const string multKeyLocation = "./key_mult.bin";
static const string rotKeyLocation = "./key_rot.bin";
static const string ccLocation = "./cc.bin";
static const string inputLocation = "./in.bin";
static const string outputLocation = "./out.bin";


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
};

vector<Ciphertext<DCRTPoly>> encrypt_and_serialize_plaintext(CryptoContext<DCRTPoly> cc, KeyPair<DCRTPoly> keys, vector<Plaintext> plaintexts, vector<double> input);
void serialize_keys(CryptoContext<DCRTPoly> cc);
CryptoContext<DCRTPoly> get_context_ckks();
