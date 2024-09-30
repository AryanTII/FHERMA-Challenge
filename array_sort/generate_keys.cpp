#include "generate_keys.h"


int main() {
    
    // CKKS parameters
    SecretKeyDist secretKeyDist = UNIFORM_TERNARY;
    SecurityLevel securityLevel = SecurityLevel::HEStd_NotSet; // HEStd_128_classic
    uint32_t ringDim = 256; // no
    ScalingTechnique rescaleTech = FLEXIBLEAUTO; //FIXEDAUTO
    usint firstMod = 60; // example simple-ckks-bootstrapping

    // Bootstrapping parameters
    std::vector<uint32_t> levelBudget = {4, 4};
    uint32_t levelsAvailableAfterBootstrap = 24; 
    usint depth = levelsAvailableAfterBootstrap + FHECKKSRNS::GetBootstrapDepth(levelBudget, secretKeyDist);
    // std::cout << "Bootstrapping Depth: " << FHECKKSRNS::GetBootstrapDepth(levelBudget, secretKeyDist) << std::endl;

    // Setup
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetSecretKeyDist(secretKeyDist);
    parameters.SetSecurityLevel(securityLevel);
    parameters.SetRingDim(ringDim); //no
    parameters.SetScalingTechnique(rescaleTech);
    parameters.SetFirstModSize(firstMod);
    parameters.SetMultiplicativeDepth(depth);

    // Generate crypto context
    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(FHE);

    ringDim = cc->GetRingDimension(); // if security level given instead of ring dimension
    cout << "CKKS scheme is using ring dimension " << ringDim << endl << endl;
    usint numSlots = ringDim / 2; // maximum number of slots that can be used for full packing
    cc->EvalBootstrapSetup(levelBudget);

    // Key generation
    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);
    cc->EvalRotateKeyGen(keys.secretKey, {1, -1, 2, -2, 4, -4, 8, -8, 16, -16, 32, -32, 64, -64});
    cc->EvalBootstrapKeyGen(keys.secretKey, numSlots);
    
    // Serialize into binary files
    std::cout << "Serializing Relevant Keys and Inputs!" << std::endl;
    
    if (!Serial::SerializeToFile(ccLocation, cc, SerType::BINARY)) {
        std::cerr << "Error serializing crypto context to cc.bin." << std::endl;
        std::exit(1);
    }

    if (!Serial::SerializeToFile(pubKeyLocation, keys.publicKey, SerType::BINARY)) {
        std::cerr << "Error serializing public key to pub.bin." << std::endl;
        std::exit(1);
    }

    if (!Serial::SerializeToFile(privKeyLocation, keys.secretKey, SerType::BINARY)) {
        std::cerr << "Error serializing private key to priv.bin." << std::endl;
        std::exit(1);
    }


    std::ofstream multKeyFile(multKeyLocation, std::ios::out | std::ios::binary);
    if (!cc->SerializeEvalMultKey(multKeyFile, SerType::BINARY)) {
        std::cerr << "Error serializing evaluation multiplication key to mult.bin." << std::endl;
        std::exit(1);
    }
    multKeyFile.close();


    std::ofstream rotKeyFile(rotKeyLocation, std::ios::out | std::ios::binary);
    if (!cc->SerializeEvalAutomorphismKey(rotKeyFile, SerType::BINARY)) {
        std::cerr << "Error serializing evaluation rotation key to rot.bin." << std::endl;
        std::exit(1);
    }
    rotKeyFile.close();


    // ------------------- Dummy Input for local testing -------------------
    // uint32_t batchSize = 8;
    // Input Vector
    vector<double> input = {3.0, 1.0, 4.0, 1.5, 5.0, 9.0, 2.0, 6.0};
    for (int index = 8; index < 128; index++) {
        input.push_back(2.0 + (double)index);
    }  

    Plaintext plaintext = cc->MakeCKKSPackedPlaintext(input);
    std::cout << "Input vector: " << plaintext << std::endl;

    Ciphertext<DCRTPoly> ciphertext = cc->Encrypt(keys.publicKey, plaintext);

    // // Serialize input
    if (!Serial::SerializeToFile(inputLocation, ciphertext, SerType::BINARY)) {
        std::cerr << "Error serializing input file" << std::endl;
        std::exit(1);
    }
    
    std::cout << "Serialization completed successfully!" << std::endl;

    return 0;
}
