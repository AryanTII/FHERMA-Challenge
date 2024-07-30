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

    array_limit = 8; //2048
    // array_limit = m_cc->GetEncodingParams()->GetBatchSize();

    // ------------- Generation of Masks ------------------------------
    std::vector<double> mask_odd(array_limit);
    std::vector<double> mask_even(array_limit);
    std::vector<double> mask_zero(array_limit);
    std::vector<double> mask_one(array_limit);

    for (int i = 0; i < array_limit; ++i) {
        if ( (i==0) || (i==array_limit-1)){
            mask_zero[i] = 1;
            mask_one[i]  = 0;
        } else {
            mask_zero[i] = 0;
            mask_one[i]  = 1;
        }

        if (i % 2 == 0) {
            mask_odd[i] = 1.0;
            mask_even[i] = 0.0;
        } else {
            mask_odd[i] = 0.0;
            mask_even[i] = 1.0;
        }
    }

    // Binary Masks
    m_MaskOdd  = m_cc->MakeCKKSPackedPlaintext(mask_odd);  //10101...0
    m_MaskEven = m_cc->MakeCKKSPackedPlaintext(mask_even); //01010...1
    m_MaskZero = m_cc->MakeCKKSPackedPlaintext(mask_zero); //10000...1
    m_MaskOne  = m_cc->MakeCKKSPackedPlaintext(mask_one);  //01111...0
}

Ciphertext<DCRTPoly> SortCKKS::compare(Ciphertext<DCRTPoly> m_InputA, Ciphertext<DCRTPoly> m_InputB){

    // ------------- Start of Dummy ------------------------------
    vector<double> result = {1.0, 0.0, 1.0, 0.0, 1.0, 0.0, 1.0, 0.0};
    Plaintext result_plaintext = m_cc->MakeCKKSPackedPlaintext(result);
    Ciphertext<DCRTPoly> result_ciphertext = m_cc->Encrypt(m_PublicKey, result_plaintext);
    return result_ciphertext;
    // ------------- End of Dummy ------------------------------

}

Ciphertext<DCRTPoly> SortCKKS::swap(Ciphertext<DCRTPoly> a, bool is_even){

    auto b = m_cc->EvalRotate(a, 1);
    auto c = compare(a, b);
    auto X = m_cc->EvalAdd(m_cc->EvalMult(c, m_cc->EvalSub(b,a)), a); // c*(b - a)+a

    auto b_ = m_cc->EvalRotate(a, -1);
    auto c_ = compare(b_, a);
    auto Y  = m_cc->EvalAdd(m_cc->EvalMult(c_, m_cc->EvalSub(b_, a)), a);  // c_*(b_ - a)+a

    Ciphertext<DCRTPoly> result;

    if (is_even == true) {
        result = m_cc->EvalAdd(m_cc->EvalMult(X, m_MaskOdd), m_cc->EvalMult(Y, m_MaskEven));
    }
    else {
        result = m_cc->EvalAdd(m_cc->EvalMult(X, m_MaskEven), m_cc->EvalMult(Y, m_MaskOdd));
        result = m_cc->EvalAdd(m_cc->EvalMult(a, m_MaskZero), m_cc->EvalMult(result, m_MaskOne));
    }
    return result;
}

void SortCKKS::eval(){

    auto tempPoly = m_InputC;

    for(int iter = 0; iter < array_limit; iter++){
        tempPoly = swap(tempPoly, true);
        tempPoly = swap(tempPoly, false);
    }

    // Sorted vector
    m_OutputC = tempPoly;
}

void SortCKKS::deserializeOutput(){

    if (!Serial::SerializeToFile(m_OutputLocation, m_OutputC, SerType::BINARY))
    {
        std::cerr << " Could not serialize output ciphertext" << std::endl;
    }
}



