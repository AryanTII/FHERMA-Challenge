#include "lookup.h"
LookUp::LookUp(std::string ccLocation, std::string pubKeyLocation, std::string multKeyLocation,
                   std::string rotKeyLocation, std::string inputLocation, std::string indexLocation, std::string outputLocation)
    : m_PubKeyLocation(pubKeyLocation), m_MultKeyLocation(multKeyLocation), m_RotKeyLocation(rotKeyLocation),
      m_CCLocation(ccLocation), m_InputLocation(inputLocation), m_IndexLocation(indexLocation), m_OutputLocation(outputLocation)
{
    initCC();
};

void LookUp::initCC()
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

    if (!Serial::DeserializeFromFile(m_IndexLocation, m_IndexC, SerType::BINARY))
    {
        std::cerr << "Could not deserialize index file" << std::endl;
        std::exit(1);
    }

    array_limit = 8;
    plaintextModulus = m_cc->GetCryptoParameters()->GetPlaintextModulus();
    plaintextModulus_log = std::log2(plaintextModulus);
}

void LookUp::eval()
{
    std::vector<int64_t> mask_one(array_limit, 1);
    Plaintext m_One = m_cc->MakePackedPlaintext(mask_one);

    std::vector<int64_t> ind_array(array_limit); 
    for(usint iter = 0; iter < array_limit; iter++){
        ind_array[iter] = iter;
    }
    Plaintext index_array = m_cc->MakePackedPlaintext(ind_array);
    
    // Start of Stage 1: index_sub should have 0 in input index and non-zero otherwise
    // Rotate and subtract index
    auto index_rot = m_IndexC;
    auto index_sub = m_cc->EvalSub(index_array, index_rot);

    for(usint iter = 1; iter < array_limit; iter++){
        index_rot = m_cc->EvalRotate(index_rot, -1);
        index_sub = m_cc->EvalSub(index_sub, index_rot);
    }
    // End of Stage 1: index_sub has 0 in input index and non-zero otherwise


    // Start of Stage 2: index_sub should have 1 in input index and 0 otherwise
    for(double iter = 0; iter < plaintextModulus_log; iter++){
        index_sub = m_cc->EvalSquare(index_sub);
    }
    // 1 - (A-B)^{p-1}
    index_sub = m_cc->EvalSub(m_One, index_sub);
    // End of Stage 2: index_sub has 1 in input index and 0 otherwise

    
    
    // Start of Stage 3: Compute inner product at first location     
    index_sub = m_cc->EvalMult(index_sub, m_InputC);
    
    auto index_inner = index_sub;
    for(usint iter = 1; iter < array_limit; iter++){
        index_sub = m_cc->EvalRotate(index_sub, 1);
        index_inner = m_cc->EvalAdd(index_inner, index_sub);
    }
    // End of Stage 3: Compute inner product at first location 
    
    // Create a mask to extract the first element
    vector<int64_t> maskVector(array_limit, 0);
    maskVector[0] = 1;
    Plaintext maskPlaintext = m_cc->MakePackedPlaintext(maskVector);
    m_OutputC = m_cc->EvalMult(index_inner, maskPlaintext);
}

void LookUp::deserializeOutput()      
{

    if (!Serial::SerializeToFile(m_OutputLocation, m_OutputC, SerType::BINARY))
    {
        std::cerr << " Could not serialize output ciphertext" << std::endl;
    }
}
