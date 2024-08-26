#include "generate_keys.h"


int main() {

    // CKKS parameters    
    uint32_t multDepth = 29;
    uint32_t scaleMod = 59;
    usint firstMod = 60;
    ScalingTechnique rescaleTech = FLEXIBLEAUTO; //Custom
    // ----------- Alternate ------------------- 
    // uint32_t scaleMod = 78;//59;
    // usint firstMod = 89;//60;
    // ScalingTechnique rescaleTech = FIXEDAUTO; //Custom
    // ----------- Alternate -------------------
    uint32_t batchSize = 65536;
    uint32_t levelsAvailableAfterBootstrap = 10; 
    usint depth = levelsAvailableAfterBootstrap + multDepth;
    // std::vector<uint32_t> levelBudget = {4, 4};
    std::vector<uint32_t> levelBudget = {2, 2};
    std::vector<uint32_t> bsgsDim = {0, 0};

    // Setup CKKS parameters
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetBatchSize(batchSize);
    parameters.SetScalingModSize(scaleMod);
    parameters.SetScalingTechnique(rescaleTech);
    parameters.SetFirstModSize(firstMod);
    // parameters.SetMultiplicativeDepth(multDepth); //Initial
    parameters.SetMultiplicativeDepth(depth);
    
    // Generate crypto context
    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(FHE);

    usint ringDim = cc->GetRingDimension();
    // This is the maximum number of slots that can be used for full packing.
    usint numSlots = ringDim / 2;
    cout << "CKKS scheme is using ring dimension " << ringDim << endl << endl;

    // cc->EvalBootstrapSetup(levelBudget); //Simple
    cc->EvalBootstrapSetup(levelBudget, bsgsDim, numSlots); //Advanced

    // Key generation
    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);
    cc->EvalAtIndexKeyGen(keys.secretKey, {1});
    cc->EvalRotateKeyGen(keys.secretKey, {1, -1});
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

    Plaintext plaintext = cc->MakeCKKSPackedPlaintext(input);
    std::cout << "Input vector: " << plaintext << std::endl;

    Ciphertext<DCRTPoly> ciphertext = cc->Encrypt(keys.publicKey, plaintext);

    // // Serialize input
    if (!Serial::SerializeToFile(inputLocation, ciphertext, SerType::BINARY)) {
        std::cerr << "Error serializing input file" << std::endl;
        std::exit(1);
    }
    
    std::cout << "Serialization completed successfully!" << std::endl;


    // -------------------------- Dummy Bootstrap testing -------------------
    // std::cout << "Number of levels used out of 29: " << ciphertext->GetLevel() << std::endl;

    // auto ciphertext1 = cc->EvalMult(ciphertext, ciphertext);
    // std::cout << "Number of levels used out of 29: " << ciphertext1->GetLevel() << std::endl;

    // auto ciphertext2 = cc->EvalMult(ciphertext1, ciphertext1);
    // std::cout << "Number of levels used out of 29: " << ciphertext2->GetLevel() << std::endl;

    // Bootstrapping
    // auto tempPolyNew = cc->EvalBootstrap(ciphertext2);
    // std::cout << "Number of levels used out of 29 (New): " << tempPolyNew->GetLevel() << std::endl;

    // ------------------- End of Dummy Bootstrap testing -------------------

    return 0;
}
