#include "generate_keys.h"

int main() {

    CryptoContext<DCRTPoly> m_cc;
    PublicKey<DCRTPoly> m_PublicKey;
    PrivateKey<DCRTPoly> m_PrivateKey;
    Ciphertext<DCRTPoly> m_InputC;
    Ciphertext<DCRTPoly> m_OutputC;

    if (!Serial::DeserializeFromFile(ccLocation, m_cc, SerType::BINARY))
    {
        cerr << "Could not deserialize cryptocontext file" << endl;
        exit(1);
    }

    if (!m_cc) {
        cerr << "Deserialized crypto context is invalid" << endl;
        exit(1);
    }

    if (!Serial::DeserializeFromFile(privKeyLocation, m_PrivateKey, SerType::BINARY))
    {
        cerr << "Could not deserialize private key file" << endl;
        exit(1);
    }

    if (!m_PrivateKey) {
        cerr << "Deserialized private key is invalid" << endl;
        exit(1);
    }

    if (!Serial::DeserializeFromFile(inputLocation, m_InputC, SerType::BINARY))
    {
        cerr << "Could not deserialize input file" << endl;
        exit(1);
    }

    if (!Serial::DeserializeFromFile(outputLocation, m_OutputC, SerType::BINARY))
    {
        cerr << "Could not deserialize output file" << endl;
        exit(1);
    }

    if (!m_InputC || !m_OutputC) {
        cerr << "Deserialized ciphertext is invalid" << endl;
        exit(1);
    }

    cout << "De-serialization for validation completed successfully!" << endl;
    cout << endl;

    Plaintext plaintextInput, plaintextOutput;

    try {
        m_cc->Decrypt(m_PrivateKey, m_InputC, &plaintextInput);
        m_cc->Decrypt(m_PrivateKey, m_OutputC, &plaintextOutput);
    } catch (const lbcrypto::OpenFHEException& e) {
        cerr << "OpenFHEException caught: " << e.what() << endl;
        exit(1);
    } catch (const exception& e) {
        cerr << "Standard exception caught: " << e.what() << endl;
        exit(1);
    } catch (...) {
        cerr << "Unknown exception caught." << endl;
        exit(1);
    }


    uint32_t array_limit = 8;
    plaintextInput->SetLength(array_limit);
    plaintextOutput->SetLength(array_limit);

    cout.precision(2);
    
    cout << "Input  Plaintext:" << fixed << setprecision(5) << plaintextInput << endl;
    cout << "Output Plaintext:" << fixed << setprecision(5) << plaintextOutput << endl;


    vector<double> desired_output;
    vector<double> error_output(array_limit);
    ifstream desiredOutput("../files/desired_output_sort.txt");
    if (desiredOutput.is_open()) {
        double value;
        while (desiredOutput >> value) {
            desired_output.push_back(value);
        }
        desiredOutput.close();

        for (size_t i = 0; i < array_limit; ++i) {
            error_output[i] = desired_output[i] - plaintextOutput->GetCKKSPackedValue()[i].real();
        }

        cout << "Desired sorted output: ";
        for (const auto& value : desired_output) {
            cout << value << " ";
        }
        cout << endl;

        cout << "Error in computation: ";
        for (const auto& value : error_output) {
            cout << value << " ";
        }
        cout << endl;

    } else {
        cerr << "Unable to open file for reading." << endl;
    }

    cout << "Result validation completed!" << endl;

    return 0;

}