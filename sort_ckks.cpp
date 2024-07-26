#include "sort_ckks.h"

SortCKKS::SortCKKS(std::string ccLocation, std::string pubKeyLocation, std::string multKeyLocation,
                         std::string rotKeyLocation,
                         std::string inputLocation,
                         std::string outputLocation)
    : m_PubKeyLocation(pubKeyLocation),
      m_MultKeyLocation(multKeyLocation),
      m_RotKeyLocation(rotKeyLocation),
      m_CCLocation(ccLocation),
      m_InputLocation(inputLocation),
      m_OutputLocation(outputLocation)
{
    initCC();
};

void SortCKKS::initCC(){

    // m_cc->ClearEvalMultKeys();
    // m_cc->ClearEvalAutomorphismKeys();
    // CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
    if (!Serial::DeserializeFromFile(m_CCLocation, m_cc, SerType::BINARY))
    {
        std::cerr << "Could not deserialize cryptocontext file" << std::endl;
        std::exit(1);
    }

    if (!Serial::DeserializeFromFile(m_PubKeyLocation, m_PublicKey, SerType::BINARY))
    {
        std::cerr << "Could not deserialize public key file" << std::endl;
        std::exit(1);
    }

    std::ifstream multKeyIStream(m_MultKeyLocation, std::ios::in | std::ios::binary);
    if (!multKeyIStream.is_open())
    {
        std::exit(1);
    }
    if (!m_cc->DeserializeEvalMultKey(multKeyIStream, SerType::BINARY))
    {
        std::cerr << "Could not deserialize rot key file" << std::endl;
        std::exit(1);
    }
    multKeyIStream.close();

    std::ifstream rotKeyIStream(m_RotKeyLocation, std::ios::in | std::ios::binary);
    if (!rotKeyIStream.is_open())
    {
        std::exit(1);
    }

    if (!m_cc->DeserializeEvalAutomorphismKey(rotKeyIStream, SerType::BINARY))
    {
        std::cerr << "Could not deserialize eval rot key file" << std::endl;
        std::exit(1);
    }
    rotKeyIStream.close();

    if (!Serial::DeserializeFromFile(m_InputLocation, m_InputC, SerType::BINARY))
    {
        std::cerr << "Could not deserialize cryptocontext file" << std::endl;
        std::exit(1);
    }
}

void SortCKKS::eval(){

    std::cout << "This is the sorting method that needs to be filled" << std::endl;
    std::cout << "The output should be the ciphertext on m_OutputC" << std::endl;
    
    // To be filled
    m_OutputC = m_InputC;
}

void SortCKKS::deserializeOutput(){

    if (!Serial::SerializeToFile(m_OutputLocation, m_OutputC, SerType::BINARY))
    {
        std::cerr << " Could not serialize output ciphertext" << std::endl;
    }
}

void SortCKKS::viewInputOutput(KeyPair<DCRTPoly> keys, uint32_t batchSize){

    // Decrypt the ciphertexts
    Plaintext plaintextInput, plaintextOutput;
    // m_cc->SetPrivateKey(keys.secretKey);
    m_cc->Decrypt(keys.secretKey, m_InputC, &plaintextInput);
    m_cc->Decrypt(keys.secretKey, m_OutputC, &plaintextOutput);

    plaintextInput->SetLength(batchSize);
    plaintextOutput->SetLength(batchSize);
    
    std::cout << "Input Plaintext:" << plaintextInput << std::endl;
    std::cout << "Output Plaintext:" << plaintextOutput << std::endl;
    std::cout << std::endl;
}

// void SortCKKS::viewInputOutput(CryptoContext<DCRTPoly> cc, KeyPair<DCRTPoly> keys, uint32_t batchSize){

//     // Decrypt the ciphertexts
//     Plaintext plaintextInput, plaintextOutput;
//     cc->Decrypt(keys.secretKey, m_InputC, &plaintextInput);
//     cc->Decrypt(keys.secretKey, m_OutputC, &plaintextOutput);

//     plaintextInput->SetLength(batchSize);
//     plaintextOutput->SetLength(batchSize);
    
//     std::cout << "Input Plaintext:" << plaintextInput << std::endl;
//     std::cout << "Output Plaintext:" << plaintextOutput << std::endl;
//     std::cout << std::endl;
// }