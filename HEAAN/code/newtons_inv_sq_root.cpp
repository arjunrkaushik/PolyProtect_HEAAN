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

// Newtons method
// y1 = y*(3 - x*pow(y,2)) / 2
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
        test1[i] = complex<double>((i+1)*(i+1), 0.0);
        test2[i] = complex<double>(1.0, 0.0);
        zero[i] = complex<double>(i+1, 0.0);
    }

    Ciphertext x, y, cipher_zero;
    scheme.encrypt(x, test1, n, logp, logq);
    scheme.encrypt(y, test2, n, logp, logq);
    int cnt = 3;

    while(cnt > 0){
        Ciphertext k, y_squared;
        algo.powerOf2(y_squared, y, logp, 1);
        // cout << y.logq << " "  << y.logp << endl;
        // cout << "y^2 = " << y_squared.logq << " "  << y_squared.logp << endl;
        if(x.logq > y_squared.logq){
            scheme.modDownByAndEqual(x, x.logq - y_squared.logq);
        }
        else if(x.logq < y_squared.logq){
            scheme.modDownByAndEqual(y_squared, y_squared.logq - x.logq);
        }
        scheme.mult(k, x, y_squared);
        // cout << "x = " << x.logq << " "  << x.logp << endl;
        // cout << "y^2 = " << y_squared.logq << " "  << y_squared.logp << endl;
        scheme.reScaleByAndEqual(k, k.logp - logp);
        // cout << "k = " << k.logq << " "  << k.logp << endl;
        scheme.multByConstAndEqual(k, -1.0, logp);
        scheme.reScaleByAndEqual(k, k.logp - logp);
        // cout << "k = " << k.logq << " "  << k.logp << endl;
        scheme.addConstAndEqual(k, 3.0, k.logp);
        // cout << "k = " << k.logq << " "  << k.logp << endl;
        scheme.multByConstAndEqual(k, 0.5, k.logp);
        scheme.reScaleByAndEqual(k, k.logp - logp);
        if(k.logq > y.logq){
            scheme.modDownByAndEqual(k, k.logq - y.logq);
        }
        else if(k.logq < y.logq){
            scheme.modDownByAndEqual(y, y.logq - k.logq);
        }
        scheme.multAndEqual(k, y);
        scheme.reScaleByAndEqual(k, k.logp - logp);
        y.copy(k);
        k.free();
        cnt--;
    }
    cout << "Result : " << "logq = " << y.logq << " logp = "  << y.logp << endl;
    
    complex<double>* decrypt_p = scheme.decrypt(secretKey, y);

    StringUtils::compare(zero, decrypt_p, n, "prod");

    
}