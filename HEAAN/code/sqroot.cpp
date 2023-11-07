#include "../src/HEAAN.h"

#include <NTL/BasicThreadPool.h>
#include <NTL/ZZ.h>
#include <cmath>
#include <complex>
#include <vector>
#include <algorithm>

#include <fstream>

#include <iostream>
#include <opencv2/opencv.hpp>
#include <opencv2/imgcodecs.hpp>
#include <opencv2/core/mat.hpp>
#include <string>
#include <random>

#include "../src/Ciphertext.h"
#include "../src/EvaluatorUtils.h"
#include "../src/Ring.h"
#include "../src/Scheme.h"
#include "../src/SchemeAlgo.h"
#include "../src/SecretKey.h"
#include "../src/StringUtils.h"
#include "../src/TimeUtils.h"
#include "../src/SerializationUtils.h"

// #include "polyprotect_mobio.h"

using namespace cv;
using namespace heaan;
using namespace std;
using namespace NTL;

int main() {

    long logq = 800; ///< Ciphertext Modulus
	long logp = 30; ///< Real message will be quantized by multiplying 2^40
	long logn = 2; ///< log2(The number of slots)

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

    complex<double>* test1 = new complex<double>[n];    
    // complex<double>* test2 = new complex<double>[n];
    // complex<double>* zero = new complex<double>[n];

    for (long i = 0; i < n; i++){
        test1[i] = complex<double>((double)(i+1), 0.0);
    }

    Ciphertext y, x2;
    scheme.encrypt(y, test1, n, logp, logq);
    scheme.encrypt(x2, test1, n, logp, logq);

    scheme.multByConstAndEqual(x2, complex<double>(0.5,0), logp);
    



    
    complex<double>* true_val = new complex<double>[n];
    complex<double> temp(0.0,0.0);
    for (long i = 0; i < n; i++) {
        true_val[i] = pow(test2[i],2) - pow(test1[i], 2);
    }

    complex<double>* decrypt_p = scheme.decrypt(secretKey, test2_cipher_sq);

    StringUtils::compare(true_val, decrypt_p, n, "prod");

    
}