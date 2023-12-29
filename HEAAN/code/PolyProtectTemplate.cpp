#include "PolyProtectTemplate.h"

#include <iterator>
#include <fstream>
#include <streambuf>
#include <cmath>
#include <filesystem>
#include <dirent.h>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <vector>
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
#include "../src/HEAAN.h"
#include "../src/Ciphertext.h"
#include "../src/EvaluatorUtils.h"
#include "../src/Ring.h"
#include "../src/Scheme.h"
#include "../src/SchemeAlgo.h"
#include "../src/SecretKey.h"
#include "../src/StringUtils.h"
#include "../src/TimeUtils.h"
#include "../src/SerializationUtils.h"

using namespace heaan;
using namespace std;
using namespace NTL;

vector<long> PolyProtectTemplate::generateC(long C_range, long m) {
    // Randomly generates m coefficients for the PolyProtect mapping.

    // **Inputs:**

    // C_range : integer
    //     The absolute min/max values of the coefficients range. 

    // m : int
    //     The number of coefficients to generate.

    // **Outputs:**

    // C : 1D numpy array of integers
    //     Array of m coefficients.


    vector<long> neg_range, pos_range, whole_range;

    for (long i = -1*C_range; i < 0; i++) {
        neg_range.push_back(i);
    }
    for (long i = 1; i < C_range + 1; i++) {
        neg_range.push_back(i);
    }
    for (auto i:neg_range) {
        whole_range.push_back(i);
    }
    for (auto i:pos_range) {
        whole_range.push_back(i);
    }

    shuffle(whole_range.begin(), whole_range.end(), random_device());
    
    vector<long> C(whole_range.begin(), whole_range.begin() + m);

    return C;

}

vector<long> PolyProtectTemplate::generateE(long m) {
    // Randomly generates m exponents for the PolyProtect mapping.

    // **Inputs:**

    // m : int
    //     The number of exponents to generate.

    // **Outputs:**

    // E : 1D numpy array of integers
    //     Array of m exponents.

    

    vector<long> E;

    for (long i = 1; i < m + 1; i++) {
        E.push_back(i);
    }

    shuffle(E.begin(), E.end(), random_device());

    return E;    

}

vector<Ciphertext> PolyProtectTemplate::generateTemplate(vector<Ciphertext> embeddings_ciphers, long cipher_m, long m, SecretKey &secretKey, Scheme &scheme, SchemeAlgo &algo, long logp, long logq) {
    long C_range = 50;   
    vector<long> C = generateC(C_range, m);
    vector<long> E = generateE(m);
    
    vector<Ciphertext> polyProtect;
    for (int i = 0; i < embeddings_ciphers.size(); i++) {
        complex<double>* zero = new complex<double>[cipher_m];
        for (long j = 0; j < cipher_m; j++) {
            zero[j] = complex<double>(0.0,0.0);
        }
        Ciphertext temp_p;
        scheme.encrypt(temp_p, zero, cipher_m ,logp, logq);

        for (long j = 0; j < m; j++) {
            complex<double>* temp = new complex<double>[cipher_m];
            for (long k = 0; k < cipher_m; k++) {
                temp[k] = complex<double>(0.0,0.0);
            }
            temp[j] = complex<double>(1.0, 0.0);
            
            Ciphertext temp_word, res;
            scheme.encrypt(temp_word, temp, cipher_m, logp, logq);
            scheme.multAndEqual(temp_word, embeddings_ciphers[i]);
            algo.power(res, temp_word, logp, E[j]);
            scheme.multByConstAndEqual(res, C[j], logp);
            scheme.reScaleByAndEqual(res, res.logp - logp);
            if (temp_p.logq > res.logq) {
                scheme.modDownToAndEqual(temp_p, res.logq);
            }
            else if (temp_p.logq < res.logq){
                scheme.modDownToAndEqual(res, temp_p.logq);
            }
            scheme.addAndEqual(temp_p, res);          

            temp_word.free();
            res.free();
            // break;
        }
        cout << "Summing " << i << endl; 
        Ciphertext temp_sum_cipher;
        for (long j = m; j > 0; j--){
            scheme.leftRotateFastAndEqual(temp_sum_cipher, 1);
            scheme.addAndEqual(temp_sum_cipher, temp_p);
        }

        polyProtect.push_back(temp_sum_cipher);
        temp_sum_cipher.free();
        // delete[] v0;   
        cout << "Template Ready " << i << endl;     
    }

    return polyProtect;
}
