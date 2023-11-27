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
    complex<double>* test2 = new complex<double>[n];
    complex<double>* zero = new complex<double>[n];
    
    for (long i = 0; i < n; i++){
        test1[i] = complex<double>((double)(i+1), 0.0);
        test2[i] = complex<double>((double)(i+2), 0.0);
        zero[i] = complex<double>(0.0, 0.0);
    }

    Ciphertext test1_cipher, test2_cipher, prod_cipher;
    scheme.encrypt(test1_cipher, test1, n, logp, logq);
    scheme.encrypt(test2_cipher, test2, n, logp, logq);
    // scheme.encrypt(prod_cipher, zero, n, logp, logq);

    scheme.mult(prod_cipher, test1_cipher, test2_cipher);
    
    Ciphertext sum_cipher;
    sum_cipher.copy(prod_cipher);
    sum_cipher.logp = prod_cipher.logp;
    sum_cipher.logq = prod_cipher.logq;
    //perform sum of all elements in Prod
    for (long j = n-1; j > 0; j--){
        scheme.leftRotateFastAndEqual(prod_cipher, 1);
        scheme.addAndEqual(sum_cipher, prod_cipher);
    }

    // Denominator
    Ciphertext cipher1_sq, cipher2_sq;
    algo.powerOf2(cipher1_sq, test1_cipher, logp, 1);
    algo.powerOf2(cipher2_sq, test2_cipher, logp, 1);

    Ciphertext sq_sum1, sq_sum2;
    
    // Sum of squares for test1
    sq_sum1.copy(cipher1_sq);
    sq_sum1.logp = cipher1_sq.logp;
    sq_sum1.logq = cipher1_sq.logq;
    for (long j = n-1; j > 0; j--){
        scheme.leftRotateFastAndEqual(cipher1_sq, 1);
        scheme.addAndEqual(sq_sum1, cipher1_sq);
    }

    // Sum of squares for test2
    sq_sum2.copy(cipher2_sq);
    sq_sum2.logp = cipher2_sq.logp;
    sq_sum2.logq = cipher2_sq.logq;
    for (long j = n-1; j > 0; j--){
        scheme.leftRotateFastAndEqual(cipher2_sq, 1);
        scheme.addAndEqual(sq_sum2, cipher2_sq);
    }

    // Ciphertext inv11;
    // algo.inverse(inv1, sq_sum1, logp, 10);
    scheme.multByConstAndEqual(sq_sum1, double(1.0/64.0), sq_sum1.logp);
    cout << sq_sum1.logp << " " << sq_sum1.logq << endl;
    Ciphertext clog;
    scheme.reScaleByAndEqual(sq_sum1, sq_sum1.logp - logp);
    cout << sq_sum1.logp << " " << sq_sum1.logq << endl;
    // algo.function(clog, sq_sum1, LOGARITHM, logp, 10);
    algo.function(clog, test1_cipher, LOGARITHM, logp, 2);
    complex<double>* true_val = new complex<double>[n];
    complex<double> temp(0.0,0.0);
    for (long i = 0; i < n; i++) {
        true_val[i] = log(test1[i]);
    }
    //true_val[0] = log(temp/64.0);

    // for (long i = 0; i < n; i++) {
    //     true_val[i] = log(test1[i]);
    // }
    complex<double>* decrypt_p = scheme.decrypt(secretKey, clog);

    StringUtils::compare(true_val, decrypt_p, n, "prod");

    
}