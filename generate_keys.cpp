#include "generate_keys.h"


int main() {

    // CKKS parameters
    uint32_t multDepth = 29;
    uint32_t scaleModSize = 59;
    uint32_t batchSize = 65536;

    // Setup CKKS parameters
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetBatchSize(batchSize);

    // Generate crypto context
    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKESchemeFeature::PKE);
    cc->Enable(PKESchemeFeature::FHE);
    cc->Enable(PKESchemeFeature::LEVELEDSHE);

    // Key generation
    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);
    cc->EvalAtIndexKeyGen(keys.secretKey, {1});
    cc->EvalRotateKeyGen(keys.secretKey, {1, 2, -1, -2});

    // Serialize into binary files
    std::cout << "GENERATING KEYS!" << std::endl;
    
    if (!Serial::SerializeToFile(ccLocation, cc, SerType::BINARY)) {
        std::cerr << "Error serializing crypto context to cryptoContext.txt." << std::endl;
        std::exit(1);
    }

    if (!Serial::SerializeToFile(pubKeyLocation, keys.publicKey, SerType::BINARY)) {
        std::cerr << "Error serializing public key to public_key.txt." << std::endl;
        std::exit(1);
    }


    std::ofstream multKeyFile(multKeyLocation, std::ios::out | std::ios::binary);
    if (!cc->SerializeEvalMultKey(multKeyFile, SerType::BINARY)) {
        std::cerr << "Error serializing evaluation multiplication key to mult_key.txt." << std::endl;
        std::exit(1);
    }
    multKeyFile.close();


    std::ofstream rotKeyFile(rotKeyLocation, std::ios::out | std::ios::binary);
    if (!cc->SerializeEvalAutomorphismKey(rotKeyFile, SerType::BINARY)) {
        std::cerr << "Error serializing evaluation rotation key to rotKey.txt." << std::endl;
        std::exit(1);
    }
    rotKeyFile.close();


    // ------------------- Dummy Input for local testing -------------------
    // uint32_t batchSize = 8;
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

    return 0;
}
