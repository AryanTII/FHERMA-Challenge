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

    array_limit = 8; // 2048
    // array_limit = m_cc->GetEncodingParams()->GetBatchSize();
}

void LookUp::eval()
{
    std::cout << " To be filled" << std::endl;
    // m_OutputC = m_InputC;
    std::cout << " Deadline is August 06... Hurry Up" << std::endl;

    std::vector<int64_t> mask_one(array_limit, 1);
    std::vector<int64_t> mask_field(array_limit, 32768);
    Plaintext m_One = m_cc->MakePackedPlaintext(mask_one);
    Plaintext m_Field = m_cc->MakePackedPlaintext(mask_field);

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
    // This is not complete
    // std::vector<Ciphertext<DCRTPoly>> ciphertextVec(5, index_sub);

    for(usint iter = 0; iter < 10; iter++){
        index_sub = m_cc->EvalSquare(index_sub);
        // index_sub = m_cc->EvalMultMany(ciphertextVec);
        std::cout << "(Iter " << iter+1 <<  ") - Number of levels used: " << index_sub->GetLevel() << std::endl;
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

    m_OutputC = index_inner;
    std::cout << "Number of levels used in m_OutputC: " << m_OutputC->GetLevel() << std::endl;

}

void LookUp::deserializeOutput()
{

    if (!Serial::SerializeToFile(m_OutputLocation, m_OutputC, SerType::BINARY))
    {
        std::cerr << " Could not serialize output ciphertext" << std::endl;
    }
}
