#include "generate_keys.h"

int main() {

    CryptoContext<DCRTPoly> m_cc;
    PublicKey<DCRTPoly> m_PublicKey;
    PrivateKey<DCRTPoly> m_PrivateKey;
    Ciphertext<DCRTPoly> m_InputC;
    Ciphertext<DCRTPoly> m_OutputC;

    if (!Serial::DeserializeFromFile(ccLocation, m_cc, SerType::BINARY))
    {
        std::cerr << "Could not deserialize cryptocontext file" << std::endl;
        std::exit(1);
    }

    if (!m_cc) {
        std::cerr << "Deserialized crypto context is invalid" << std::endl;
        std::exit(1);
    }

    if (!Serial::DeserializeFromFile(privKeyLocation, m_PrivateKey, SerType::BINARY))
    {
        std::cerr << "Could not deserialize private key file" << std::endl;
        std::exit(1);
    }

    if (!m_PrivateKey) {
        std::cerr << "Deserialized private key is invalid" << std::endl;
        std::exit(1);
    }

    if (!Serial::DeserializeFromFile(inputLocation, m_InputC, SerType::BINARY))
    {
        std::cerr << "Could not deserialize input file" << std::endl;
        std::exit(1);
    }

    if (!Serial::DeserializeFromFile(outputLocation, m_OutputC, SerType::BINARY))
    {
        std::cerr << "Could not deserialize output file" << std::endl;
        std::exit(1);
    }

    if (!m_InputC || !m_OutputC) {
        std::cerr << "Deserialized ciphertext is invalid" << std::endl;
        std::exit(1);
    }

    std::cout << "De-serialization for validation completed successfully!" << std::endl;
    std::cout << std::endl;

    Plaintext plaintextInput, plaintextOutput;

    try {
        m_cc->Decrypt(m_PrivateKey, m_InputC, &plaintextInput);
        m_cc->Decrypt(m_PrivateKey, m_OutputC, &plaintextOutput);
    } catch (const lbcrypto::OpenFHEException& e) {
        std::cerr << "OpenFHEException caught: " << e.what() << std::endl;
        std::exit(1);
    } catch (const std::exception& e) {
        std::cerr << "Standard exception caught: " << e.what() << std::endl;
        std::exit(1);
    } catch (...) {
        std::cerr << "Unknown exception caught." << std::endl;
        std::exit(1);
    }


    uint32_t batchSize = 8;
    plaintextInput->SetLength(batchSize);
    plaintextOutput->SetLength(batchSize);

    std::cout.precision(2);
    
    std::cout << "Input Plaintext:" << std::fixed << std::setprecision(2) << plaintextInput << std::endl;
    std::cout << "Output Plaintext:" << std::fixed << std::setprecision(2) << plaintextOutput << std::endl;

    std::cout << "Result validation completed!" << std::endl;

    return 0;

}