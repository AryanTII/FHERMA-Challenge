#include "sort_ckks.h"
#include <ctime> // to remove

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

    std::vector<uint32_t> levelBudget = {4, 4};
    m_cc->EvalBootstrapSetup(levelBudget); //Simple Bootstrapping Setup

    array_limit = 128;
    Norm_Value = 255.0;
    Norm_Value_Inv = 1.0/Norm_Value;


    // ------------- Generation of Masks ------------------------------
    

}


Ciphertext<DCRTPoly> SortCKKS::cond_swap_mergesort(Ciphertext<DCRTPoly> a, int step, bool is_initial, int array_limit){
    cout << "\nStep: " << step;
    auto b = m_cc->EvalRotate(a, step);
    
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

    auto min_by_2_cipher = m_cc->EvalSub(sum_cipher, abs_diff); // 2 * min = (a+b - |a-b|)
    auto sum_by_2_cipher = m_cc->EvalMult(2, sum_cipher);
    auto max_by_2_cipher = m_cc->EvalSub(sum_by_2_cipher, min_by_2_cipher); // 2 * max = 2 * (a+b) - 2 * min_cipher
    max_by_2_cipher = m_cc->EvalRotate(max_by_2_cipher, -step);
    
    std::vector<double> mask1(array_limit);
    std::vector<double> mask2(array_limit);
    if (is_initial == true) {
        for (int i = 0; i < array_limit; ++i) {
            if ((i / step) % 2 == 0) {
                mask1[i] = 0.5;
                mask2[i] = 0;
            } else {
                mask1[i] = 0;
                mask2[i] = 0.5;
            }
        }
    }
    else {
        for (int i = 0; i < array_limit; ++i) {
            if (((i / step) == 0) || ((i / step) % 2 == 1 && i < array_limit - step)) {
                mask1[i] = 0.5;
                mask2[i] = 0;
            } else {
                mask1[i] = 0;
                mask2[i] = 0.5;
            }
        }
    }
    // cout << "\nmask1: " << mask1;
    // cout << "\nmask2: " << mask2;
    auto m_Mask1 = m_cc->MakeCKKSPackedPlaintext(mask1);
    auto m_Mask2 = m_cc->MakeCKKSPackedPlaintext(mask2);
    m_Mask1->SetLength(array_limit);
    m_Mask2->SetLength(array_limit);

    auto result = m_cc->EvalAdd(m_cc->EvalMult(min_by_2_cipher, m_Mask1), m_cc->EvalMult(max_by_2_cipher, m_Mask2));

    return result;
}


void SortCKKS::eval_test()
{   
    time_t start, finish;
    time_t start1, finish1;
    time_t start2, finish2;
    time_t start3, finish3;
    time_t tot_start, tot_finish;

    m_cc->Enable(ADVANCEDSHE);

    auto tempPoly = m_cc->EvalMult(m_InputC, Norm_Value_Inv);

    time(&tot_start);

    int section, step, count;
    section = 2;
    count = 0;
    while(section <= array_limit){
        step = section / 2;
        time(&start);
        tempPoly = cond_swap_mergesort(tempPoly, step, true, array_limit);
        time(&finish);
        cout << "\ncond_swap time = " << difftime(finish, start) << " seconds";
        count = count + 1;
        // if (count % 2 == 0 && (step != 1 || section != array_limit)) {
            time(&start1);
            tempPoly = m_cc->EvalBootstrap(tempPoly);
            time(&finish1);
            cout << "\nbootstrap time = " << difftime(finish1, start1) << " seconds";
        // }
        step = step / 2;
        while(step > 0){
            time(&start2);
            tempPoly = cond_swap_mergesort(tempPoly, step, false, array_limit);
            time(&finish2);
            cout << "\ncond_swap time = " << difftime(finish2, start2) << " seconds";
            count = count + 1;
            // if (count % 2 == 0 && (step != 1 || section != array_limit)) {
                time(&start3);
                tempPoly = m_cc->EvalBootstrap(tempPoly);
                time(&finish3);
                cout << "\nbootstrap time = " << difftime(finish3, start3) << " seconds";
            // }
            step = step / 2;
        }
        section = section * 2;
    }
    time(&tot_finish);
    cout << "\nTotal time = " << difftime(tot_finish, tot_start) << " seconds";

    // De-Normalizing
    tempPoly = m_cc->EvalMult(tempPoly, Norm_Value);

    // Sorted vector
    m_OutputC = tempPoly;
}




void SortCKKS::eval()
{
    m_cc->Enable(ADVANCEDSHE);

    auto tempPoly = m_InputC;

    // for(int iter = 0; iter < array_limit/2; iter++){
    //     tempPoly = cond_swap(tempPoly, true);
    //     tempPoly = cond_swap(tempPoly, false);
    // }

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

