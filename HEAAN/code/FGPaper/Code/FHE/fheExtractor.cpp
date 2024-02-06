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

    string path = "/home/csgrad/kaushik3/PolyProtect/PolyProtect_HEAAN/HEAAN/code/FGPaper/Code/MRL+PP/PP_AdaFace_Celebset_output.txt";
    ifstream file(path);

    if (!file.is_open()) {
        cerr << "Failed to open the file: " << path << endl;
    }

    vector<vector<complex<double>>> inputVals;

    string line;
    while (getline(file, line)) {
        vector<complex<double>> input;
        istringstream iss(line);
        double realPart;
        while (iss >> realPart) {
            // if (!(realPart)){
            //     // cout << "Why zero now" << endl;
            //     // cerr << "Invalid float number on line: " << line << endl;
            //     cerr << "Invalid float number: " << realPart << endl;
            // }
            complex<double> number = complex<double>(realPart, 0.0);
            input.push_back(number);
        }
        
        inputVals.push_back(input);
    }
    file.close();
    cout << inputVals.size() << " X " << inputVals[0].size() << endl;

    // complex<double>* tempInput = new complex<double>[n];
    // for(long j = 0; j < n; j++){
    //     tempInput[j] = complex<double>(0.0, 0.0);
    // }
    // for(int j = 0; j < inputVals[0].size(); j++){
    //     tempInput[j] = inputVals[0][j];
    // }
    // Ciphertext temp;
    // scheme.encrypt(temp, tempInput, n, logp, logq);

    // // cout << temp.ax.size() << endl;
    // int cnt = 0;
    // for(int i = 0; i < n; i++){
    //     cout << temp.ax[i] << endl;
    //     cout << endl;
    //     ostringstream oss;
    //     oss << temp.ax[i];
    //     string myString = oss.str();
    //     cout << myString << endl;
    //     cout << endl;
    //     cout << temp.bx[i] << endl;
    //     cout << endl;
    //     long long myInteger2 = NTL::to_long(temp.bx[i]);
    //     cout << to_string(myInteger2) << endl;
    //     cout << endl;
    //     cnt++;
    //     break;
    // }
    // cout << cnt << endl;

    // vector<Ciphertext> inputCiphers;

    ofstream outputFile("PP+FHE_AdaFace_Celebset.txt");
    for(int i = 0; i < inputVals.size(); i++){
        if(i%300 == 0){
            cout << i << endl;
        }
        complex<double>* tempInput = new complex<double>[n];
        for(long j = 0; j < n; j++){
            tempInput[j] = complex<double>(0.0, 0.0);
        }
        for(int j = 0; j < inputVals[i].size(); j++){
            tempInput[j] = inputVals[i][j];
        }
        Ciphertext temp;
        scheme.encrypt(temp, tempInput, n, logp, logq);
        string cipherDump = "";
        for(int j = 0; j < n; j++){
            ostringstream oss;
            oss << temp.ax[j];
            string myString = oss.str();
            cipherDump += myString;
        }
        for(int j = 0; j < n; j++){
            ostringstream oss;
            oss << temp.bx[j];
            string myString = oss.str();
            cipherDump += myString;
        }

        cipherDump += "\n";
        outputFile << cipherDump; 
    }

    outputFile.close();


    // complex<double>* decrypt_p = scheme.decrypt(secretKey, num_sum);

    // StringUtils::compare(zero, decrypt_p, n, "prod");

    
}