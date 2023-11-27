#include "../src/HEAAN.h"

#include <NTL/BasicThreadPool.h>
#include <NTL/ZZ.h>
#include <cmath>
#include <complex>
#include <vector>
#include <algorithm>

#include <fstream>

#include <iostream>
// #include <opencv2/opencv.hpp>
// #include <opencv2/imgcodecs.hpp>
// #include <opencv2/core/mat.hpp>
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

// using namespace cv;
using namespace heaan;
using namespace std;
using namespace NTL;

// Newtons method
// y1 = y*(3 - x*pow(y,2)) / 2
int main() {

    long logq = 800; ///< Ciphertext Modulus
	long logp = 30; ///< Real message will be quantized by multiplying 2^40
	long logn = 1; ///< log2(The number of slots)

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
    complex<double>* corr = new complex<double>[n];
    
    for (long i = 0; i < n; i++){
        test1[i] = complex<double>(i*0.25, 0.0);
        test2[i] = complex<double>(0.0, 0.0);
        corr[i] = complex<double>(2.0, 0.0);
    }

    Ciphertext x, y, result;
    scheme.encrypt(x, test1, n, logp, logq);
    scheme.encrypt(result, test2, n, logp, logq);
    
    double a = -30.03885434;
    double b = 116.31448582;
    double c = -259.73613335;
    double d = 327.30513602;
    double e = -215.87621696;
    double f = 57.83789459;
    double g = 5.2091446960660654;
    vector<double> coeff{a, b, c, d, e, f};

    Ciphertext power_x;
    power_x.copy(x);
    int power = 1;

    while (power <= 6) {
        Ciphertext x1;
        scheme.multByConst(x1, power_x, coeff[power-1], logp);
        
        scheme.reScaleByAndEqual(x1, x1.logp - logp);

        scheme.modDownByAndEqual(result, result.logq - x1.logq);
        scheme.addAndEqual(result, x1);

        if(power > 1) {
            scheme.modDownByAndEqual(x, x.logq - power_x.logq);
        }
        if(power < 6){
            scheme.multAndEqual(power_x, x);
            scheme.reScaleByAndEqual(power_x, power_x.logp - logp);
        }
        
        x1.free();
        power++;
    }

    scheme.addConstAndEqual(result, g, logp);

    cout << "Result : " << "logq = " << result.logq << " logp = " << result.logp << endl;
    complex<double>* decrypt_p = scheme.decrypt(secretKey, result);

    StringUtils::compare(corr, decrypt_p, n, "prod");

    
}