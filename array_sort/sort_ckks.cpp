#include "sort_ckks.h"

SortCKKS::SortCKKS(std::string ccLocation, std::string pubKeyLocation, std::string multKeyLocation,
                   std::string rotKeyLocation, std::string inputLocation, std::string outputLocation)
    : m_PubKeyLocation(pubKeyLocation), m_MultKeyLocation(multKeyLocation), m_RotKeyLocation(rotKeyLocation),
      m_CCLocation(ccLocation), m_InputLocation(inputLocation), m_OutputLocation(outputLocation)
{
    initCC();
};

void SortCKKS::initCC()
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

    array_limit = 8; // 2048 
    Norm_Value = 255.0;
    Norm_Value_Inv = 1.0/Norm_Value;

    // ------------- Generation of Masks ------------------------------
    std::vector<double> mask_odd(array_limit);
    std::vector<double> mask_even(array_limit);
    std::vector<double> mask_zero(array_limit);
    std::vector<double> mask_one(array_limit);

    for (int i = 0; i < array_limit; ++i) 
    {
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
        }
        else
        {
            mask_odd[i] = 0.0;
            mask_even[i] = 1.0;
        }
    }

    m_MaskOdd  = m_cc->MakeCKKSPackedPlaintext(mask_odd);  //10101...0
    m_MaskEven = m_cc->MakeCKKSPackedPlaintext(mask_even); //01010...1
    m_MaskZero = m_cc->MakeCKKSPackedPlaintext(mask_zero); //10000...1
    m_MaskOne  = m_cc->MakeCKKSPackedPlaintext(mask_one);  //01111...0

    // m_MaskOdd->SetLength(array_limit);
    // m_MaskEven->SetLength(array_limit);
    // m_MaskZero->SetLength(array_limit);
    // m_MaskOne->SetLength(array_limit);
}



Ciphertext<DCRTPoly> SortCKKS::cond_swap(Ciphertext<DCRTPoly> a, bool is_even){

    auto b = m_cc->EvalRotate(a, 1);

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

    auto min_cipher = m_cc->EvalMult(0.5, m_cc->EvalSub(sum_cipher, abs_diff)); // 1/2 * (a+b - |a-b|)
    auto max_cipher = m_cc->EvalSub(sum_cipher, min_cipher); // (a+b) - min_cipher
    max_cipher = m_cc->EvalRotate(max_cipher, -1);

    Ciphertext<DCRTPoly> result;

    if (is_even == true) {
        result = m_cc->EvalAdd(m_cc->EvalMult(min_cipher, m_MaskOdd), m_cc->EvalMult(max_cipher, m_MaskEven));
    }
    else {
        result = m_cc->EvalAdd(m_cc->EvalMult(min_cipher, m_MaskEven), m_cc->EvalMult(max_cipher, m_MaskOdd));
        result = m_cc->EvalAdd(m_cc->EvalMult(a, m_MaskZero), m_cc->EvalMult(result, m_MaskOne));
    }
    return result;
}



void SortCKKS::eval_test()
{
    // ------- Just for testing -----------
    usint mult_depth = 0;
    // Open the file for reading
    std::ifstream paramsFile("../files/genkey_params_sort.txt");
    if (paramsFile.is_open()) {
        paramsFile >> mult_depth;
        paramsFile.close();
    } else {
        std::cerr << "Unable to open file for reading." << std::endl;
    }
    // -------------------------------------


    // Normalizing
    auto tempPoly = m_cc->EvalMult(m_InputC, Norm_Value_Inv);
    cout << "Number of levels used out of " << mult_depth << ": " << tempPoly->GetLevel() << endl;
    cout << "Number of levels remaining: " << mult_depth - tempPoly->GetLevel() << endl;

    cout << "Start of iteration " << endl;

    // ------------ Iteration 1 ----------------------
    tempPoly = cond_swap(tempPoly, true);
    // Bootstrapping
    tempPoly = m_cc->EvalBootstrap(tempPoly);
    cout << "Number of levels used out of " << mult_depth << ": " << tempPoly->GetLevel() << endl;
    cout << "Number of levels remaining: " << mult_depth - tempPoly->GetLevel() << endl;

    tempPoly = cond_swap(tempPoly, false);
    // Bootstrapping
    tempPoly = m_cc->EvalBootstrap(tempPoly);
    cout << "Number of levels used out of " << mult_depth << ": " << tempPoly->GetLevel() << endl;
    cout << "Number of levels remaining: " << mult_depth - tempPoly->GetLevel() << endl;

    // ------------ Iteration 2 ----------------------
    tempPoly = cond_swap(tempPoly, true);
    // Bootstrapping
    tempPoly = m_cc->EvalBootstrap(tempPoly);
    cout << "Number of levels used out of " << mult_depth << ": " << tempPoly->GetLevel() << endl;
    cout << "Number of levels remaining: " << mult_depth - tempPoly->GetLevel() << endl;

    tempPoly = cond_swap(tempPoly, false);
    // Bootstrapping
    tempPoly = m_cc->EvalBootstrap(tempPoly);
    cout << "Number of levels used out of " << mult_depth << ": " << tempPoly->GetLevel() << endl;
    cout << "Number of levels remaining: " << mult_depth - tempPoly->GetLevel() << endl;

    // // ------------ Iteration 3 ----------------------
    // tempPoly = cond_swap(tempPoly, true);
    // // Bootstrapping
    // tempPoly = m_cc->EvalBootstrap(tempPoly);
    // cout << "Number of levels used out of " << mult_depth << ": " << tempPoly->GetLevel() << endl;
    // cout << "Number of levels remaining: " << mult_depth - tempPoly->GetLevel() << endl;

    // tempPoly = cond_swap(tempPoly, false);
    // // Bootstrapping
    // tempPoly = m_cc->EvalBootstrap(tempPoly);
    // cout << "Number of levels used out of " << mult_depth << ": " << tempPoly->GetLevel() << endl;
    // cout << "Number of levels remaining: " << mult_depth - tempPoly->GetLevel() << endl;

    // // ------------ Iteration 4 ----------------------
    // tempPoly = cond_swap(tempPoly, true);
    // // Bootstrapping
    // tempPoly = m_cc->EvalBootstrap(tempPoly);
    // cout << "Number of levels used out of " << mult_depth << ": " << tempPoly->GetLevel() << endl;
    // cout << "Number of levels remaining: " << mult_depth - tempPoly->GetLevel() << endl;

    // tempPoly = cond_swap(tempPoly, false);
    // // Bootstrapping
    // tempPoly = m_cc->EvalBootstrap(tempPoly);
    // cout << "Number of levels used out of " << mult_depth << ": " << tempPoly->GetLevel() << endl;
    // cout << "Number of levels remaining: " << mult_depth - tempPoly->GetLevel() << endl;
    // // ------------------------------------------------

    // De-Normalizing
    tempPoly = m_cc->EvalMult(tempPoly, Norm_Value);

    // Sorted vector
    m_OutputC = tempPoly;
}




void SortCKKS::eval()
{
    // m_cc->Enable(ADVANCEDSHE);

    // auto tempPoly = m_InputC;
    // Normalizing
    auto tempPoly = m_cc->EvalMult(m_InputC, Norm_Value_Inv);
    cout << "Number of levels used out of 31: " << tempPoly->GetLevel() << endl;
    cout << "Number of levels remaining: " << 31 - tempPoly->GetLevel() << endl;

    for(int iter = 0; iter < array_limit/2; iter++){

        tempPoly = cond_swap(tempPoly, true);
        // Bootstrapping
        tempPoly = m_cc->EvalBootstrap(tempPoly);
        cout << "Number of levels used out of 31: " << tempPoly->GetLevel() << endl;
        cout << "Number of levels remaining: " << 31 - tempPoly->GetLevel() << endl;

        tempPoly = cond_swap(tempPoly, false);
        // Bootstrapping
        tempPoly = m_cc->EvalBootstrap(tempPoly);
        cout << "Number of levels used out of 31: " << tempPoly->GetLevel() << endl;
        cout << "Number of levels remaining: " << 31 - tempPoly->GetLevel() << endl;
    }

    // De-Normalizing
    tempPoly = m_cc->EvalMult(tempPoly, Norm_Value);

    // Sorted vector
    m_OutputC = tempPoly;
}

void SortCKKS::deserializeOutput()
{

    if (!Serial::SerializeToFile(m_OutputLocation, m_OutputC, SerType::BINARY))
    {
        std::cerr << " Could not serialize output ciphertext" << std::endl;
    }
}

