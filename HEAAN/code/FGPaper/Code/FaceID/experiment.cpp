#include "../../../../src/HEAAN.h"

#include <iterator>
#include <fstream>
#include <sstream>
#include <streambuf>
#include <cmath>
#include <filesystem>
#include <dirent.h>
#include <iomanip>
#include <chrono>
#include <ctime>

#include <iostream>
#include <sys/resource.h>
#include <omp.h>
#include <cstdlib>
#include <NTL/xdouble.h>
#include <NTL/ZZ.h>
#include "NTL/RR.h"
#include <NTL/ZZX.h>
#include "NTL/mat_RR.h"
#include "NTL/vec_RR.h"
#include "../../../../src/Ciphertext.h"
#include "../../../../src/EvaluatorUtils.h"
#include "../../../../src/Ring.h"
#include "../../../../src/Scheme.h"
#include "../../../../src/SchemeAlgo.h"
#include "../../../../src/SecretKey.h"
#include "../../../../src/StringUtils.h"
#include "../../../../src/TimeUtils.h"
#include "../../../../src/SerializationUtils.h"

// #include "polyprotect_mobio.h"

using namespace heaan;
using namespace std;
using namespace NTL;

vector<string> extractData(string path) {
    std::ifstream inputFile(path);

    // Check if the file is open
    if (!inputFile.is_open()) {
        std::cerr << "Error opening the file." << std::endl;
        return {}; // Exit with an error code
    }

    // Define a vector to store each row of data
    std::vector<std::vector<std::string>> data;

    // Read the file line by line
    std::string line;
    while (std::getline(inputFile, line)) {
        std::vector<std::string> row;
        std::stringstream ss(line);
        std::string cell;

        // Split the line into cells using a comma as the delimiter
        while (std::getline(ss, cell, ',')) {
            row.push_back(cell);
        }

        // Add the row to the data vector
        data.push_back(row);
    }

    // Close the file
    inputFile.close();

    // for (const auto& row : data) {
    //     for (const auto& cell : row) {
    //         std::cout << cell << " ";
    //     }
    //     std::cout << std::endl;
    // }

    vector<string> id;
    for(auto i : data) {
        id.push_back(i[i.size() - 1]);
    }
    return id;
}

int main() {

    long logq = 800; ///< Ciphertext Modulus
	long logp = 30; ///< Real message will be quantized by multiplying 2^40
	long logn = 9; ///< log2(The number of slots)

	srand(time(NULL));
	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);
	SchemeAlgo algo(scheme);
    scheme.addLeftRotKey(secretKey, 2);
    scheme.addLeftRotKey(secretKey, 1);
    long n = 1 << logn;

    vector<string> id = extractData("/home/csgrad/kaushik3/PolyProtect/PolyProtect_HEAAN/HEAAN/code/FGPaper/Data/BFW/bfw_id.csv");
    
}