#include "helper.h"

void serialize_keys(CryptoContext<DCRTPoly> cc){

    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);
    cc->EvalAtIndexKeyGen(keys.secretKey, {1});

    if (!Serial::SerializeToFile("cc.bin", cc, SerType::BINARY)) {
        std::cerr << "Error serializing crypto context to cryptoContext.txt." << std::endl;
        std::exit(1);
    }

    if (!Serial::SerializeToFile("key_pub.bin", keys.publicKey, SerType::BINARY)) {
        std::cerr << "Error serializing public key to public_key.txt." << std::endl;
        std::exit(1);
    }


    std::ofstream multKeyFile("key_mult.bin", std::ios::out | std::ios::binary);
    if (!cc->SerializeEvalMultKey(multKeyFile, SerType::BINARY)) {
        std::cerr << "Error serializing evaluation multiplication key to mult_key.txt." << std::endl;
        std::exit(1);
    }
    multKeyFile.close();


    std::ofstream rotKeyFile("key_rot.bin", std::ios::out | std::ios::binary);
    if (!cc->SerializeEvalAutomorphismKey(rotKeyFile, SerType::BINARY)) {
        std::cerr << "Error serializing evaluation rotation key to rotKey.txt." << std::endl;
        std::exit(1);
    }
    rotKeyFile.close();
}

CryptoContext<DCRTPoly> get_context_ckks(){
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
    return cc;
}
