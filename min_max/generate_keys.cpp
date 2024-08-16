#include "generate_keys.h"

std::vector<double> EvalChebyshevCoefficients(std::function<double(double)> func, double a, double b, uint32_t degree) {
    if (!degree) {
        OPENFHE_THROW("The degree of approximation can not be zero");
    }
    // the number of coefficients to be generated should be degree+1 as zero is also included
    size_t coeffTotal{degree + 1};
    double bMinusA = 0.5 * (b - a);
    double bPlusA  = 0.5 * (b + a);
    double PiByDeg = M_PI / static_cast<double>(coeffTotal);
    std::vector<double> functionPoints(coeffTotal);
    for (size_t i = 0; i < coeffTotal; ++i)
        functionPoints[i] = func(std::cos(PiByDeg * (i + 0.5)) * bMinusA + bPlusA);

    double multFactor = 2.0 / static_cast<double>(coeffTotal);
    std::vector<double> coefficients(coeffTotal);
    for (size_t i = 0; i < coeffTotal; ++i) {
        for (size_t j = 0; j < coeffTotal; ++j)
            coefficients[i] += functionPoints[j] * std::cos(PiByDeg * i * (j + 0.5));
        coefficients[i] *= multFactor;
    }
    return coefficients;
}


int main() {

    // CKKS parameters
    uint32_t ring_dimension = 4096;//131072;//32768;
    uint32_t multDepth = 22;
    uint32_t scaleMod = 59;
    usint firstMod = 60;
    uint32_t batchSize = 2048;//65536;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetScalingModSize(scaleMod);
    parameters.SetFirstModSize(firstMod);
    parameters.SetBatchSize(batchSize);
    ScalingTechnique rescaleTech = FLEXIBLEAUTO;
    parameters.SetScalingTechnique(rescaleTech);

    parameters.SetSecurityLevel(SecurityLevel::HEStd_NotSet);
    parameters.SetRingDim(ring_dimension);

    // Bootstrapping
    SecretKeyDist secretKeyDist = UNIFORM_TERNARY;
    parameters.SetSecretKeyDist(secretKeyDist);
    std::vector<uint32_t> levelBudget = {4, 4};
    // std::vector<uint32_t> bsgsDim = {0, 0};
    uint32_t levelsAvailableAfterBootstrap = 30;
    usint depth = levelsAvailableAfterBootstrap + multDepth;//FHECKKSRNS::GetBootstrapDepth(levelBudget, secretKeyDist);
    parameters.SetMultiplicativeDepth(depth);

    std::ofstream paramsFile("genkey_params.txt");
    if (paramsFile.is_open()) {
        paramsFile << depth;
        paramsFile.close();
        std::cout << "Multiplicative depth has been written to build/genkey_params.txt" << std::endl;
    } else {
        std::cerr << "Unable to open file for writing." << std::endl;
    }

    std::cout << "Parameters: " << parameters << std::endl;  // prints all parameter values

    // Generate crypto context
    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(FHE);

    usint ringDim = cc->GetRingDimension();
    usint numSlots = ringDim / 2; // Bootstrapping
    cout << "CKKS scheme is using ring dimension " << ringDim << endl << endl;

    cc->EvalBootstrapSetup(levelBudget); //Simple // Bootstrapping
    // cc->EvalBootstrapSetup(levelBudget, bsgsDim, numSlots); //Advanced

    // Key generation
    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);
    cc->EvalRotateKeyGen(keys.secretKey, {1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024});
    cc->EvalBootstrapKeyGen(keys.secretKey, numSlots); // Bootstrapping


    // Serialize into binary files
    std::cout << "Serializing Relevant Keys and Inputs!" << std::endl;
    
    if (!Serial::SerializeToFile(ccLocation, cc, SerType::BINARY)) {
        std::cerr << "Error serializing crypto context to cc.bin." << std::endl;
        std::exit(1);
    }

    if (!Serial::SerializeToFile(pubKeyLocation, keys.publicKey, SerType::BINARY)) {
        std::cerr << "Error serializing public key to pub.bin." << std::endl;
        std::exit(1);
    }

    if (!Serial::SerializeToFile(privKeyLocation, keys.secretKey, SerType::BINARY)) {
        std::cerr << "Error serializing private key to priv.bin." << std::endl;
        std::exit(1);
    }


    std::ofstream multKeyFile(multKeyLocation, std::ios::out | std::ios::binary);
    if (!cc->SerializeEvalMultKey(multKeyFile, SerType::BINARY)) {
        std::cerr << "Error serializing evaluation multiplication key to mult.bin." << std::endl;
        std::exit(1);
    }
    multKeyFile.close();


    std::ofstream rotKeyFile(rotKeyLocation, std::ios::out | std::ios::binary);
    if (!cc->SerializeEvalAutomorphismKey(rotKeyFile, SerType::BINARY)) {
        std::cerr << "Error serializing evaluation rotation key to rot.bin." << std::endl;
        std::exit(1);
    }
    rotKeyFile.close();

    // --------------------------------------------------------------------
    int array_limit = 2048;  // Set this to your desired size
    std::vector<double> input;
    input.reserve(array_limit);

    double largestElement = 0;

    // Seed the random number generator
    srand(static_cast<unsigned>(time(0)));

    for (int i = 0; i < array_limit; ++i) {
        double randomValue = rand() % 256;  // Generate a random integer between 0 and 255
        input.push_back(randomValue);

        // Update largest element
        if (randomValue > largestElement) {
            largestElement = randomValue;
        }
    }

    // Plaintext plaintext = cc->MakeCKKSPackedPlaintext(input);
    Plaintext plaintext = cc->MakeCKKSPackedPlaintext(input, 1, 0, nullptr, numSlots);
    // std::cout << "Input vector: " << plaintext << std::endl;
    Ciphertext<DCRTPoly> ciphertext = cc->Encrypt(keys.publicKey, plaintext);
    // std::cout << "Desired Output: " << largestElement << std::endl;
    std::ofstream desiredOutputFile("desired_output.txt");
    if (desiredOutputFile.is_open()) {
        desiredOutputFile << largestElement;
        desiredOutputFile.close();
        std::cout << "Desired output has been written to build/desired_output.txt" << std::endl;
    } else {
        std::cerr << "Unable to open file for writing." << std::endl;
    }
    // --------------------------------------------------------------------

    // // Serialize input
    if (!Serial::SerializeToFile(inputLocation, ciphertext, SerType::BINARY)) {
        std::cerr << "Error serializing input file" << std::endl;
        std::exit(1);
    }
    
    std::cout << "Serialization completed successfully!" << std::endl;

    // --------------------------------------------------------------------
    // Choosing a higher degree yields better precision, but a longer runtime.
    uint32_t polyDegree = 500;
    std::vector<double> coefficients = EvalChebyshevCoefficients([](double x) -> double { return std::abs(x); }, -1, 1, polyDegree);

    // Writing the coefficients to a file in the desired format
    std::ofstream outputFile("chebyshev_coefficients.txt");
    if (outputFile.is_open()) {
        outputFile << "EvalChebyshevCoefficients for abs function with polyDegree: " << polyDegree << "\n";
        outputFile << "std::vector<double> coeff_abs({\n";
        outputFile << std::fixed << std::setprecision(17);  // Set precision for floating point numbers

        for (size_t i = 0; i < coefficients.size(); ++i) {
            outputFile << coefficients[i];
            if (i != coefficients.size() - 1) {
                outputFile << ",";
            }
            // Add a new line every few coefficients to keep the output readable
            if ((i + 1) % 5 == 0) {
                outputFile << "\n";
            } else {
                outputFile << " ";
            }
        }

        outputFile << "});\n";
        outputFile.close();
        std::cout << "Coefficients have been written to chebyshev_coefficients.txt" << std::endl;
    } else {
        std::cerr << "Unable to open file for writing." << std::endl;
    }
    // --------------------------------------------------------------------

    return 0;
}
