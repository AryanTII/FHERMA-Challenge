#include "generate_keys.h"


int main() {

    // CKKS parameters
    uint32_t ring_dimension = 4096;//32768;
    // uint32_t multDepth = 59;
    uint32_t scaleMod = 59;
    usint firstMod = 60;
    uint32_t batchSize = 8;
    
    // std::vector<uint32_t> bsgsDim = {0, 0};

    CCParams<CryptoContextCKKSRNS> parameters;
    // parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(scaleMod);
    parameters.SetFirstModSize(firstMod);
    parameters.SetBatchSize(batchSize);
    ScalingTechnique rescaleTech = FLEXIBLEAUTO;
    parameters.SetScalingTechnique(rescaleTech);

    parameters.SetSecurityLevel(SecurityLevel::HEStd_NotSet);
    parameters.SetRingDim(ring_dimension);

    // Bootstrapping
    SecretKeyDist secretKeyDist = UNIFORM_TERNARY;
    parameters.SetSecretKeyDist(secretKeyDist);
    std::vector<uint32_t> levelBudget = {4, 4};
    uint32_t levelsAvailableAfterBootstrap = 30;
    usint depth = levelsAvailableAfterBootstrap + FHECKKSRNS::GetBootstrapDepth(levelBudget, secretKeyDist);
    parameters.SetMultiplicativeDepth(depth);

    std::cout << "Parameters: " << parameters << std::endl;  // prints all parameter values

    // Generate crypto context
    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(FHE);

    usint ringDim = cc->GetRingDimension();
    usint numSlots = ringDim / 2; // Bootstrapping
    cout << "CKKS scheme is using ring dimension " << ringDim << endl << endl;

    cc->EvalBootstrapSetup(levelBudget); //Simple // Bootstrapping
    // cc->EvalBootstrapSetup(levelBudget, bsgsDim, numSlots); //Advanced

    // Key generation
    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);
    cc->EvalRotateKeyGen(keys.secretKey, {1, 2, 4});
    cc->EvalBootstrapKeyGen(keys.secretKey, numSlots); // Bootstrapping


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
    /*
    // Input Vector
    vector<double> input = {3, 1, 4, 15, 5, 9, 2, 6};
    // Plaintext plaintext = cc->MakeCKKSPackedPlaintext(input);
    Plaintext plaintext = cc->MakeCKKSPackedPlaintext(input, 1, 0, nullptr, numSlots);
    std::cout << "Input vector: " << plaintext << std::endl;
    Ciphertext<DCRTPoly> ciphertext = cc->Encrypt(keys.publicKey, plaintext);
    std::cout << "Desired Output: 15" << std::endl;
    */

    // --------------------------------------------------------------------
    int array_limit = 8;  // Set this to your desired size
    std::vector<double> input;
    input.reserve(array_limit);

    double largestElement = 0;

    // Seed the random number generator
    srand(static_cast<unsigned>(time(0)));

    for (int i = 0; i < array_limit; ++i) {
        double randomValue = rand() % 256;  // Generate a random integer between 0 and 255
        input.push_back(randomValue);

        // Update largest element
        if (randomValue > largestElement) {
            largestElement = randomValue;
        }
    }

    // Plaintext plaintext = cc->MakeCKKSPackedPlaintext(input);
    Plaintext plaintext = cc->MakeCKKSPackedPlaintext(input, 1, 0, nullptr, numSlots);
    std::cout << "Input vector: " << plaintext << std::endl;
    Ciphertext<DCRTPoly> ciphertext = cc->Encrypt(keys.publicKey, plaintext);
    std::cout << "Desired Output: " << largestElement << std::endl;
    // --------------------------------------------------------------------

    // std::cout << "Level Before Bootstrapping: " << depth - ciphertext->GetLevel() << std::endl;
    // ciphertext = cc->EvalBootstrap(ciphertext);
    // std::cout << "Level After Bootstrapping: " << depth - ciphertext->GetLevel() << std::endl;

    // // Serialize input
    if (!Serial::SerializeToFile(inputLocation, ciphertext, SerType::BINARY)) {
        std::cerr << "Error serializing input file" << std::endl;
        std::exit(1);
    }
    
    std::cout << "Serialization completed successfully!" << std::endl;

    return 0;
}
