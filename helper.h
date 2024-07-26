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

void serialize_keys(CryptoContext<DCRTPoly> cc);

CryptoContext<DCRTPoly> get_context_ckks();
