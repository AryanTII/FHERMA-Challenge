#include "helper.h"

// SortCKKS::SortCKKS(std::string ccLocation, std::string pubKeyLocation, std::string multKeyLocation,
//                          std::string rotKeyLocation,
//                          std::string inputLocation,
//                          std::string outputLocation)
//     : m_PubKeyLocation(pubKeyLocation),
//       m_MultKeyLocation(multKeyLocation),
//       m_RotKeyLocation(rotKeyLocation),
//       m_CCLocation(ccLocation),
//       m_InputLocation(inputLocation),
//       m_OutputLocation(outputLocation)
// {
//     initCC();
// };

// void SortCKKS::initCC(){
//     if (!Serial::DeserializeFromFile(m_CCLocation, m_cc, SerType::BINARY))
//     {
//         std::cerr << "Could not deserialize cryptocontext file" << std::endl;
//         std::exit(1);
//     }

//     if (!Serial::DeserializeFromFile(m_PubKeyLocation, m_PublicKey, SerType::BINARY))
//     {
//         std::cerr << "Could not deserialize public key file" << std::endl;
//         std::exit(1);
//     }

//     std::ifstream multKeyIStream(m_MultKeyLocation, std::ios::in | std::ios::binary);
//     if (!multKeyIStream.is_open())
//     {
//         std::exit(1);
//     }
//     if (!m_cc->DeserializeEvalMultKey(multKeyIStream, SerType::BINARY))
//     {
//         std::cerr << "Could not deserialize rot key file" << std::endl;
//         std::exit(1);
//     }
//     multKeyIStream.close();

//     std::ifstream rotKeyIStream(m_RotKeyLocation, std::ios::in | std::ios::binary);
//     if (!rotKeyIStream.is_open())
//     {
//         std::exit(1);
//     }

//     if (!m_cc->DeserializeEvalAutomorphismKey(rotKeyIStream, SerType::BINARY))
//     {
//         std::cerr << "Could not deserialize eval rot key file" << std::endl;
//         std::exit(1);
//     }
//     rotKeyIStream.close();

//     std::vector<Ciphertext<DCRTPoly>> deserializedCiphertexts;
//     std::ifstream in("in.bin", std::ios::binary);
//     if (!in.is_open()) {
//         std::cerr << "Error opening file for deserialization." << std::endl;
//         std::exit(1);
//     }
//     Serial::Deserialize(deserializedCiphertexts, in, SerType::BINARY);
//     in.close();
// }

// void SortCKKS::eval(){
//     std::cout << "To be filled" << std::endl;

// }

// vector<Ciphertext<DCRTPoly>> encrypt_and_serialize_plaintext(
//     CryptoContext<DCRTPoly> cc, KeyPair<DCRTPoly> keys, 
//     vector<Plaintext> plaintexts, vector<double> input){
//     vector<Ciphertext<DCRTPoly>> ciphertexts;
    
//     for (auto &val : input) {
//         vector<double> vec = {val};  // Create a vector from the value
//         Plaintext p = cc->MakeCKKSPackedPlaintext(vec);
//         plaintexts.push_back(p);
//         ciphertexts.push_back(cc->Encrypt(keys.publicKey, p));
//     }

//     // // Serialize input
//     if (!Serial::SerializeToFile(inputLocation, ciphertexts, SerType::BINARY)) {
//         std::cerr << "Error serializing public key to public_key.txt." << std::endl;
//         std::exit(1);
//     }


//     return ciphertexts;
// }

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
