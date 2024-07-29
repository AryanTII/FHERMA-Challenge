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
        std::cerr << "Could not deserialize input file" << std::endl;
        std::exit(1);
    }
}

Ciphertext<DCRTPoly> SortCKKS::compare(Ciphertext<DCRTPoly> m_InputA, Ciphertext<DCRTPoly> m_InputB){

    // ------------- Start of Dummy ------------------------------
    vector<double> result = {1.0, 0.0, 1.0, 0.0, 1.0, 0.0, 1.0, 0.0};

    Plaintext result_plaintext = m_cc->MakeCKKSPackedPlaintext(result);
    std::cout << "Result vector (Dummy): " << result_plaintext << std::endl;

    Ciphertext<DCRTPoly> result_ciphertext = m_cc->Encrypt(m_PublicKey, result_plaintext);
    return result_ciphertext;
    // ------------- End of Dummy ------------------------------
}

Ciphertext<DCRTPoly> SortCKKS::swap(Ciphertext<DCRTPoly> m_InputC, bool even){
    
    auto b = cc->EvalRotate(m_InputC, 1);
    c = compare(m_InputC, b)
    X = cc->EvalAdd(cc->EvalMult(c, cc->EvalSub(b,a)), a); 

    auto b_ = cc->EvalRotate(m_InputC, -1);
    c_ = compare(b_, m_InputC)
    Y = cc->EvalAdd(cc->EvalMult(c_, cc->EvalSub(b_,a)), a); 
    Ciphertext<DCRTPoly> val;
    if even
        val = cc->EvalSum(cc->EvalMult(X, m_MaskOdd), cc->EvalMult(Y, m_MaskEven))
    else    
        val = cc->EvalSum(cc->EvalMult(X, m_MaskEven), cc->EvalMult(Y, m_MaskOdd))
    return val
}

void SortCKKS::eval(){

    std::cout << "This is the sorting method that needs to be filled" << std::endl;
    std::cout << "The output should be the ciphertext on m_OutputC" << std::endl;
    std::cout << std::endl;
    
    bool isSorted = false;
    while (!isSorted)
    {
        isSorted = true;
        for (int i=1; i<=n-2; i=i+2)
        {
            m_InputC = swap(m_InputC, true)
        }
        // Perform Bubble sort on even indexed element
        for (int i=0; i<=n-2; i=i+2)
        {
            m_InputC = swap(m_InputC, false)
        }
    }
}

void SortCKKS::deserializeOutput(){

    if (!Serial::SerializeToFile(m_OutputLocation, m_OutputC, SerType::BINARY))
    {
        std::cerr << " Could not serialize output ciphertext" << std::endl;
    }
}



