#include "max_min_ckks.h"

MaxMinCKKS::MaxMinCKKS(std::string ccLocation, std::string pubKeyLocation, std::string multKeyLocation,
                   std::string rotKeyLocation, std::string inputLocation, std::string outputLocation)
    : m_PubKeyLocation(pubKeyLocation), m_MultKeyLocation(multKeyLocation), m_RotKeyLocation(rotKeyLocation),
      m_CCLocation(ccLocation), m_InputLocation(inputLocation), m_OutputLocation(outputLocation)
{
    initCC();
};

void MaxMinCKKS::initCC()
{

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

    // m_cc->Enable(PKE);
    // m_cc->Enable(KEYSWITCH);
    // m_cc->Enable(LEVELEDSHE);
    // m_cc->Enable(ADVANCEDSHE);
    // m_cc->Enable(FHE);

    std::vector<uint32_t> levelBudget = {4, 4};
    m_cc->EvalBootstrapSetup(levelBudget); //Simple Bootstrapping Setup

    array_limit = 2048; 
    Norm_Value = 255.0;
    Norm_Value_Inv = 1.0/Norm_Value;

    std::vector<double> arr_half(array_limit, 0.5);
    std::vector<double> arr_one(array_limit, 1.0);
    std::vector<double> mask_lookup(array_limit, 0); //10...0
    mask_lookup[0]  = Norm_Value; // Included de-normalization and hence changed from 1

    m_Half = m_cc->MakeCKKSPackedPlaintext(arr_half);
    m_One = m_cc->MakeCKKSPackedPlaintext(arr_one);
    m_MaskLookup  = m_cc->MakeCKKSPackedPlaintext(mask_lookup);
}


Ciphertext<DCRTPoly> MaxMinCKKS::cond_swap(const Ciphertext<DCRTPoly>& a, 
                             const Ciphertext<DCRTPoly>& b)
{
    // Compute a + b
    auto sum_cipher = m_cc->EvalAdd(a, b);
    // Compute a - b 
    auto diff_cipher = m_cc->EvalSub(a, b);

    // Choosing a higher degree yields better precision, but a longer runtime.
    // uint32_t polyDegree = 500;
    // auto abs_diff = m_cc->EvalChebyshevFunction([](double x) -> double { return std::abs(x); }, diff_cipher, -1, 1, polyDegree);
    // Using pre-computed coefficients
    // coeff_abs.resize(500); // Set number of coefficients to be used
    auto abs_diff = m_cc->EvalChebyshevSeries(diff_cipher, coeff_abs, -1, 1);


    auto result = m_cc->EvalMult(0.5, m_cc->EvalAdd(sum_cipher, abs_diff));
    return result;
}

void MaxMinCKKS::eval()
{

    // // ------- Just for testing -----------
    usint mult_depth = 0;
    // Open the file for reading
    std::ifstream paramsFile("genkey_params.txt");
    if (paramsFile.is_open()) {
        paramsFile >> mult_depth;
        paramsFile.close();
    } else {
        std::cerr << "Unable to open file for reading." << std::endl;
    }
    // // -------------------------------------
    // std::cout << "Multiplicative Depth Level available in Input: " << mult_depth - m_InputC->GetLevel() << std::endl;

    // Normalizing
    auto tempPoly = m_cc->EvalMult(m_InputC, Norm_Value_Inv);
    int k_iter = array_limit;

    while (k_iter > 1) {
        std::cout << "Level Available Before Iteration - " << k_iter<<": " << mult_depth - tempPoly->GetLevel() << std::endl;
        k_iter = k_iter >> 1;

        // auto rot_cipher = m_cc->EvalRotate(tempPoly, k_iter); // Working
        // Fast rotation variant
        auto rotc_precomp = m_cc->EvalFastRotationPrecompute(tempPoly);
        // auto rot_cipher = m_cc->EvalFastRotation(tempPoly, k_iter, 2048, rotc_precomp);
        auto rot_cipher = m_cc->EvalFastRotationExt(tempPoly, k_iter, rotc_precomp, true);
        rot_cipher  = m_cc->KeySwitchDown(rot_cipher);

        tempPoly = cond_swap(tempPoly, rot_cipher);
        // tempPoly = cond_swap_compare(tempPoly, rot_cipher); // If to use compare based approach.
        
        // std::cout << "Level Available Before Bootstrapping: " << mult_depth - tempPoly->GetLevel() << std::endl;
        tempPoly = m_cc->EvalBootstrap(tempPoly);
        // std::cout << "Level Available After Bootstrapping: " << mult_depth - tempPoly->GetLevel() << std::endl;
    }

    m_OutputC = m_cc->EvalMult(tempPoly, m_MaskLookup); // Result in first position
}

void MaxMinCKKS::deserializeOutput()
{

    if (!Serial::SerializeToFile(m_OutputLocation, m_OutputC, SerType::BINARY))
    {
        std::cerr << " Could not serialize output ciphertext" << std::endl;
    }
}


Ciphertext<DCRTPoly> MaxMinCKKS::sign(const Ciphertext<DCRTPoly> m_InputC)
{
    // coeff_sign.resize(500); // Set number of coefficients to be used
    auto result_ciphertext = m_cc->EvalChebyshevSeries(m_InputC, coeff_sign, -1, 1);
    return result_ciphertext;
}

Ciphertext<DCRTPoly> MaxMinCKKS::cond_swap_compare(const Ciphertext<DCRTPoly>& a, const Ciphertext<DCRTPoly>& b){

    auto a_minus_b = m_cc->EvalSub(a, b);
    auto a_plus_b = m_cc->EvalAdd(a, b);
    auto c = sign(a_minus_b);

    auto result = m_cc->EvalMult(0.5, m_cc->EvalAdd(a_plus_b, m_cc->EvalMult(c, a_minus_b))); // ( c *(b - a) + (b + a) ) / 2
    return result;
}

