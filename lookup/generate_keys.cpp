#include "generate_keys.h"


int main() {

    // BGV parameters
    uint32_t plaintext_modulus = 65537;
    uint32_t ring_dimension = 32768;
    uint32_t multDepth = 19;

    CCParams<CryptoContextBGVRNS> parameters;
    parameters.SetPlaintextModulus(plaintext_modulus);
    parameters.SetMultiplicativeDepth(multDepth);

    // For speed
    parameters.SetSecurityLevel(SecurityLevel::HEStd_NotSet);
    parameters.SetRingDim(ring_dimension);
    
    // Generate crypto context
    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);

    // Generate a public/private key pair
    auto keys = cc->KeyGen();
    // Generate the relinearization key
    cc->EvalMultKeyGen(keys.secretKey);
    // Generate the rotation evaluation keys
    cc->EvalRotateKeyGen(keys.secretKey, {1, 2, -1, -2});

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
    vector<int64_t> input = {3, 1, 4, 15, 5, 9, 2, 6};
    Plaintext plaintext = cc->MakePackedPlaintext(input);
    std::cout << "Input vector: " << plaintext << std::endl;
    Ciphertext<DCRTPoly> ciphertext = cc->Encrypt(keys.publicKey, plaintext);

    // Serialize input
    if (!Serial::SerializeToFile(inputLocation, ciphertext, SerType::BINARY)) {
        std::cerr << "Error serializing input file" << std::endl;
        std::exit(1);
    }

    vector<int64_t> index = {1};
    index[0] = 3;
    Plaintext index_plain = cc->MakePackedPlaintext(index);
    std::cout << "Input index: " << index_plain << std::endl;
    Ciphertext<DCRTPoly> index_cipher = cc->Encrypt(keys.publicKey, index_plain);

    std::cout << "The output should be : " << input[index[0]] << std::endl;

    // Serialize index
    if (!Serial::SerializeToFile(indexLocation, index_cipher, SerType::BINARY)) {
        std::cerr << "Error serializing index file" << std::endl;
        std::exit(1);
    }
    
    std::cout << "Serialization completed successfully!" << std::endl;

    return 0;
}
