#include "generate_keys.h"

int main() {

    // CKKS parameters    
    uint32_t multDepth = 29;
    uint32_t scaleMod = 59;
    usint firstMod = 60;
    ScalingTechnique rescaleTech = FLEXIBLEAUTO; //Custom
    // ----------- Alternate ------------------- 
    // uint32_t scaleMod = 78;//59;
    // usint firstMod = 89;//60;
    // ScalingTechnique rescaleTech = FIXEDAUTO; //Custom
    // ----------- Alternate -------------------
    uint32_t batchSize = 65536;
    uint32_t levelsAvailableAfterBootstrap = 10; 
    usint depth = levelsAvailableAfterBootstrap + multDepth;
    // vector<uint32_t> levelBudget = {4, 4};
    vector<uint32_t> levelBudget = {2, 2};
    vector<uint32_t> bsgsDim = {0, 0};

    // Setup CKKS parameters
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetBatchSize(batchSize);
    parameters.SetScalingModSize(scaleMod);
    parameters.SetScalingTechnique(rescaleTech);
    parameters.SetFirstModSize(firstMod);
    // parameters.SetMultiplicativeDepth(multDepth); //Initial
    parameters.SetMultiplicativeDepth(depth);
    
    // Generate crypto context
    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(FHE);

    usint ringDim = cc->GetRingDimension();
    // This is the maximum number of slots that can be used for full packing.
    usint numSlots = 8; //ringDim / 2;
    cout << "CKKS scheme is using ring dimension " << ringDim << endl << endl;

    // cc->EvalBootstrapSetup(levelBudget); //Simple
    cc->EvalBootstrapSetup(levelBudget, bsgsDim, numSlots); //Advanced

    // Key generation
    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);
    cc->EvalAtIndexKeyGen(keys.secretKey, {1});
    cc->EvalRotateKeyGen(keys.secretKey, {1, -1});
    cc->EvalBootstrapKeyGen(keys.secretKey, numSlots);

    // Serialize into binary files
    cout << "Serializing Relevant Keys and Inputs!" << endl;
    
    if (!Serial::SerializeToFile(ccLocation, cc, SerType::BINARY)) {
        cerr << "Error serializing crypto context to cc.bin." << endl;
        exit(1);
    }

    if (!Serial::SerializeToFile(pubKeyLocation, keys.publicKey, SerType::BINARY)) {
        cerr << "Error serializing public key to pub.bin." << endl;
        exit(1);
    }

    if (!Serial::SerializeToFile(privKeyLocation, keys.secretKey, SerType::BINARY)) {
        cerr << "Error serializing private key to priv.bin." << endl;
        exit(1);
    }


    ofstream multKeyFile(multKeyLocation, ios::out | ios::binary);
    if (!cc->SerializeEvalMultKey(multKeyFile, SerType::BINARY)) {
        cerr << "Error serializing evaluation multiplication key to mult.bin." << endl;
        exit(1);
    }
    multKeyFile.close();


    ofstream rotKeyFile(rotKeyLocation, ios::out | ios::binary);
    if (!cc->SerializeEvalAutomorphismKey(rotKeyFile, SerType::BINARY)) {
        cerr << "Error serializing evaluation rotation key to rot.bin." << endl;
        exit(1);
    }
    rotKeyFile.close();


    // --------------------------------------------------------------------
    // Generation of dummy inputs
    // --------------------------------------------------------------------
    size_t array_limit = 8;  // Set this to your desired size
    bool new_input = false;

    vector<double> desired_output(array_limit);
    vector<double> input(array_limit);

    ifstream desiredOutputFile("../files/desired_output_sort.txt");
    if (desiredOutputFile.is_open()) {
        double value;
        while (desiredOutputFile >> value) {
            desired_output.push_back(value);
        }
        desiredOutputFile.close();
        cout << "Read " << desired_output.size() << " values from desired_output_sort.txt." << endl;
    } else {
        new_input = true;

        // Initialize the random number generator
        srand(static_cast<unsigned>(time(0)));

        // Generate the first element
        desired_output[0] = (static_cast<double>(rand()) / RAND_MAX) * 200;

        // Generate subsequent elements
        for (size_t i = 1; i < array_limit; ++i) {
            double random_increment = (static_cast<double>(rand()) / RAND_MAX) * 0.1;
            desired_output[i] = desired_output[i - 1] + (i%2 + 1)*0.01 + random_increment;
        }

        ofstream outputFileSort("../files/desired_output_sort.txt");
        if (outputFileSort.is_open()) {
            for (const auto &value : desired_output) {
                outputFileSort << value << "\n";
            }
            outputFileSort.close();
            cout << "Desired output is written to desired_output_sort.txt." << endl;
        } else {
            cerr << "Unable to open desired_output_sort.txt for writing." << endl;
            return 1;
        }

    }

    cout << "Desired sorted output: ";
    for (const auto& value : desired_output) {
        cout << value << " ";
    }
    cout << endl;

    ifstream inputFile("../files/random_input_sort.txt");
    if (inputFile.is_open() && (!new_input)) {
        double value;
        while (inputFile >> value) {
            input.push_back(value);
        }
        inputFile.close();
        cout << "Read " << input.size() << " values from random_input_sort.txt." << endl;
    } else {
        cout << "File not found. Generating random values..." << endl;

        // Create input as a permuted version of desired_output
        input = desired_output;
        random_shuffle(input.begin(), input.end());

        ofstream outputFile("../files/random_input_sort.txt");
        if (outputFile.is_open()) {
            for (const auto &value : input) {
                outputFile << value << "\n";
            }
            outputFile.close();
            cout << "Random values written to random_input_sort.txt." << endl;
        } else {
            cerr << "Unable to open random_input.txt for writing." << endl;
            return 1;
        }
    }


    // --------------------------------------------------------------------
    // Input Serialization
    // --------------------------------------------------------------------
    // vector<double> input_test = {3.0, 1.0, 4.0, 1.5, 5.0, 9.0, 2.0, 6.0};

    Plaintext plaintext = cc->MakeCKKSPackedPlaintext(input); // Use input_test if needed
    cout << "Input vector: " << plaintext << endl;

    Ciphertext<DCRTPoly> ciphertext = cc->Encrypt(keys.publicKey, plaintext);

    // // Serialize input
    if (!Serial::SerializeToFile(inputLocation, ciphertext, SerType::BINARY)) {
        cerr << "Error serializing input file" << endl;
        exit(1);
    }
    
    cout << "Serialization completed successfully!" << endl;

    return 0;
}
