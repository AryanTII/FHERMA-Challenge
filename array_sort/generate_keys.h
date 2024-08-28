#include "openfhe.h"
#include "stdio.h"
#include <cmath>
#include <string>
#include <vector>
#include <cstdlib>  // for rand()
#include <ctime>    // for time()

// header files needed for serialization
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"

using namespace lbcrypto;
using namespace std;

// Key location
static const string pubKeyLocation = "../files/pub.bin";
static const string privKeyLocation = "../files/priv.bin";
static const string multKeyLocation = "../files/mult.bin";
static const string rotKeyLocation = "../files/rot.bin";
static const string ccLocation = "../files/cc.bin";
static const string inputLocation = "../files/in.bin";
static const string outputLocation = "../files/out.bin";


