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

// y1 = y*(1 + 3*x*pow(y,2)) / ( 1 + x*pow(y,2))

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

    complex<double>* val_y = new complex<double>[n];    
    complex<double>* val_x = new complex<double>[n];
    complex<double>* ans = new complex<double>[n];
    // complex<double>* o = new complex<double>[n];
    
    for (long i = 0; i < n; i++){
        val_x[i] = complex<double>((i+1)*(i+1), 0.0);
        val_y[i] = complex<double>(1.0, 0.0);
        ans[i] = complex<double>(i+1, 0.0);
        // o[i] = complex<double>(1.0, 0.0);
    }

    Ciphertext x, y;
    scheme.encrypt(x, val_x, n, logp, logq);
    scheme.encrypt(y, val_y, n, logp, logq);
    int cnt = 3;

    while(cnt > 0){
        cout << cnt << endl;
        Ciphertext k, temp, y_squared, sum_num, sum_denom, denom_inv;
        algo.powerOf2(y_squared, y, logp, 1);
        cout << y.logq << " "  << y.logp << endl;
        cout << "y^2 = " << y_squared.logq << " "  << y_squared.logp << endl;
        if(x.logq > y_squared.logq){
            scheme.modDownByAndEqual(x, x.logq - y_squared.logq);
        }
        else if(x.logq < y_squared.logq){
            scheme.modDownByAndEqual(y_squared, y_squared.logq - x.logq);
        }
        scheme.mult(temp, x, y_squared);
        cout << "x = " << x.logq << " "  << x.logp << endl;
        cout << "y^2 = " << y_squared.logq << " "  << y_squared.logp << endl;
        scheme.reScaleByAndEqual(temp, temp.logp - logp);
        // cout << "k = " << k.logq << " "  << k.logp << endl;
        

        scheme.addConst(sum_num, temp, 3.0, temp.logp);
        scheme.addConst(sum_denom, temp, 1.0, temp.logp);

        cout << "Added" << endl;        
        cout << "Num = " << sum_num.logq << " "  << sum_num.logp << endl;
        cout << "Denom = " << sum_denom.logq << " "  << sum_denom.logp << endl;
        scheme.multAndEqual(sum_num, y);
        scheme.reScaleByAndEqual(sum_num, sum_num.logp - logp);

        cout << "Mult with y" << endl;        
        cout << "Num = " << sum_num.logq << " "  << sum_num.logp << endl;
        scheme.multByConstAndEqual(sum_num, 1.0/32.0, sum_num.logp);
        scheme.reScaleByAndEqual(sum_num, sum_num.logp - logp);
        cout << "Normalized Num" << endl;
        cout << "Num = " << sum_num.logq << " "  << sum_num.logp << endl;
        scheme.multByConstAndEqual(sum_denom, 1.0/32.0, sum_denom.logp);
        scheme.reScaleByAndEqual(sum_denom, sum_denom.logp - logp);
        cout << "Normalized Denom" << endl;
        cout << "Denom = " << sum_denom.logq << " "  << sum_denom.logp << endl;
        algo.inverse(denom_inv, sum_denom, sum_denom.logp, 8);
        cout <<"Inversed" << endl;
        
        cout << "Num = " << sum_num.logq << " "  << sum_num.logp << endl;
        cout << "Denom = " << denom_inv.logq << " "  << denom_inv.logp << endl;
        if(denom_inv.logq > sum_num.logq){
            scheme.modDownByAndEqual(denom_inv, denom_inv.logq - sum_num.logq);
        }
        else if(denom_inv.logq < sum_num.logq){
            scheme.modDownByAndEqual(sum_num, sum_num.logq - denom_inv.logq);
        }

        cout << "After mod down" << endl;
        cout << "Num = " << sum_num.logq << " "  << sum_num.logp << endl;
        cout << "Denom = " << denom_inv.logq << " "  << denom_inv.logp << endl;
        scheme.mult(k, sum_num, denom_inv);
        scheme.reScaleByAndEqual(k, k.logp - logp);

        y.copy(k);
        k.free();
        temp.free(); 
        y_squared.free(); 
        sum_num.free();
        sum_denom.free(); 
        denom_inv.free();
        cnt--;
    }
    cout << y.logq << " "  << y.logp << endl;
    
    complex<double>* decrypt_p = scheme.decrypt(secretKey, y);

    StringUtils::compare(ans, decrypt_p, n, "prod");

    
}