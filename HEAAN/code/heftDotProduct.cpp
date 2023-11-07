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

void invSqRoot(Ciphertext &x, vector<vector<Ciphertext>> coeff_list, SecretKey secretKey, Scheme scheme, long logp) {
    Ciphertext result;
    for(int c = 0; c < coeff_list.size(); c++){
        cout << "Run number = " << c << endl;
        scheme.modDownByAndEqual(coeff_list[c][0], coeff_list[c][0].logq - x.logq);
        // cout << "coeff.logp = " << coeff_list[c][0].logp << "coeff.logq = " << coeff_list[c][0].logq << endl;
        // cout << "sq.logp = " << sq_sum1.logp << "sq.logq = " << sq_sum1.logq << endl;
        scheme.mult(result, x, coeff_list[c][0]);
        complex<double>* temp = scheme.decrypt(secretKey, result);
        cout << temp[0].real() << endl;
        // cout << "After mul " << "res.logp = " << result.logp << "res.logq = " << result.logq << endl;
        scheme.reScaleByAndEqual(result, result.logp - logp);
        // cout << "After rescale " << "res.logp = " << result.logp << "res.logq = " << result.logq << endl;
        scheme.modDownByAndEqual(coeff_list[c][1], coeff_list[c][1].logq - result.logq);
        // cout << "coeff.logp = " << coeff_list[c][1].logp << "coeff.logq = " << coeff_list[c][1].logq << endl;
        // cout << "res.logp = " << result.logp << "res.logq = " << result.logq << endl;
        scheme.addAndEqual(result, coeff_list[c][1]);
        complex<double>* temp2 = scheme.decrypt(secretKey, result);
        cout << temp2[0].real() << endl;
        cout << endl;
        for(int d = 2; d < coeff_list[c].size(); d++){
            cout << "Run number c = " << c << " d = " << d << endl;
            if(x.logq > result.logq){
                scheme.modDownByAndEqual(x, x.logq - result.logq);
            }
            else if(x.logq < result.logq){
                scheme.modDownByAndEqual(result, result.logq - x.logq);
            }
            // cout << "sq.logp = " << sq_sum1.logp << "sq.logq = " << sq_sum1.logq << endl;
            // cout << "res.logp = " << result.logp << "res.logq = " << result.logq << endl;
            scheme.multAndEqual(result, x);
            complex<double>* temp3 = scheme.decrypt(secretKey, result);
            cout << temp3[0].real() << endl;
            // cout << "After mul " << "res.logp = " << result.logp << "res.logq = " << result.logq << endl;
            scheme.reScaleByAndEqual(result, result.logp - logp);
            cout << "After rescale "<<"res.logp = " << result.logp << "res.logq = " << result.logq << endl;
            cout << "coeff.logp = " << coeff_list[c][d].logp << "coeff.logq = " << coeff_list[c][d].logq << endl;
            scheme.modDownByAndEqual(coeff_list[c][d], coeff_list[c][d].logq - result.logq);
            // cout << "coeff.logp = " << coeff_list[c][d].logp << "coeff.logq = " << coeff_list[c][d].logq << endl;
            // cout << "res.logp = " << result.logp << "res.logq = " << result.logq << endl;
            scheme.addAndEqual(result, coeff_list[c][d]);
            complex<double>* temp4 = scheme.decrypt(secretKey, result);
            cout << temp4[0].real() << endl;
            cout << endl;
        }
        // scheme.modDownByAndEqual(sq_sum1, sq_sum1.logq - result.logq);
        x.copy(result);
        result.free();
        cout << endl;
    }

    // return x;
}

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
        test1[i] = complex<double>((double)(i+2), 0.0);
        test2[i] = complex<double>((double)(i+2), 0.0);
        zero[i] = complex<double>(0.0, 0.0);
    }

    complex<double>* a1 = new complex<double>[n];
    complex<double>* b1 = new complex<double>[n];
    complex<double>* c1 = new complex<double>[n];
    complex<double>* d1 = new complex<double>[n];
    complex<double>* a2 = new complex<double>[n];
    complex<double>* b2 = new complex<double>[n];
    complex<double>* c2 = new complex<double>[n];
    complex<double>* d2 = new complex<double>[n];

    for(int i=0; i<n; i++)
    {
        a1[i] = complex<double>(0.33009964, 0.0);
        b1[i] = complex<double>(3.75046592, 0.0);
        c1[i] = complex<double>(-2.53130775, 0.0);
        d1[i] = complex<double>(0.60632975, 0.0);
        
        a2[i] = complex<double>(5.23381489, 0.0);
        b2[i] = complex<double>(-3.742239, 0.0);
        c2[i] = complex<double>(1.00104718, 0.0);
        d2[i] = complex<double>(-0.08817609, 0.0);
    }

    Ciphertext a1_cipher,b1_cipher,c1_cipher,d1_cipher,a2_cipher,b2_cipher,c2_cipher,d2_cipher;
    
    scheme.encrypt(a1_cipher, a1, n, logp, logq);
    scheme.encrypt(b1_cipher, b1, n, logp, logq);
    scheme.encrypt(c1_cipher, c1, n, logp, logq);
    scheme.encrypt(d1_cipher, d1, n, logp, logq);
    scheme.encrypt(a2_cipher, a2, n, logp, logq);
    scheme.encrypt(b2_cipher, b2, n, logp, logq);
    scheme.encrypt(c2_cipher, c2, n, logp, logq);
    scheme.encrypt(d2_cipher, d2, n, logp, logq);
    
    vector<vector<Ciphertext>> coeff_list;

    vector<Ciphertext> t1;
    t1.push_back(d1_cipher);
    t1.push_back(c1_cipher);
    t1.push_back(b1_cipher);
    t1.push_back(a1_cipher);
    coeff_list.push_back(t1);
    
    vector<Ciphertext> t2;
    t2.push_back(d2_cipher);
    t2.push_back(c2_cipher);
    t2.push_back(b2_cipher);
    t2.push_back(a2_cipher);
    coeff_list.push_back(t2);

    Ciphertext test1_cipher, test2_cipher, prod_cipher;
    scheme.encrypt(test1_cipher, test1, n, logp, logq);
    scheme.encrypt(test2_cipher, test2, n, logp, logq);
    // scheme.encrypt(prod_cipher, zero, n, logp, logq);

    scheme.mult(prod_cipher, test1_cipher, test2_cipher);
    
    Ciphertext sum_cipher; //Dot product
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

    scheme.multByConstAndEqual(sq_sum1, double(1.0/64.0), sq_sum1.logp);
    cout << sq_sum1.logp << " " << sq_sum1.logq << endl;
    scheme.reScaleByAndEqual(sq_sum1, sq_sum1.logp - logp);
    cout << sq_sum1.logp << " " << sq_sum1.logq << endl;
    
    
    Ciphertext result;
    for(int c = 0; c < coeff_list.size(); c++){
        cout << "Run number = " << c << endl;
        scheme.modDownByAndEqual(coeff_list[c][0], coeff_list[c][0].logq - sq_sum1.logq);
        // cout << "coeff.logp = " << coeff_list[c][0].logp << "coeff.logq = " << coeff_list[c][0].logq << endl;
        // cout << "sq.logp = " << sq_sum1.logp << "sq.logq = " << sq_sum1.logq << endl;
        scheme.mult(result, sq_sum1, coeff_list[c][0]);
        complex<double>* temp = scheme.decrypt(secretKey, result);
        cout << temp[0].real() << endl;
        // cout << "After mul " << "res.logp = " << result.logp << "res.logq = " << result.logq << endl;
        scheme.reScaleByAndEqual(result, result.logp - logp);
        // cout << "After rescale " << "res.logp = " << result.logp << "res.logq = " << result.logq << endl;
        scheme.modDownByAndEqual(coeff_list[c][1], coeff_list[c][1].logq - result.logq);
        // cout << "coeff.logp = " << coeff_list[c][1].logp << "coeff.logq = " << coeff_list[c][1].logq << endl;
        // cout << "res.logp = " << result.logp << "res.logq = " << result.logq << endl;
        scheme.addAndEqual(result, coeff_list[c][1]);
        complex<double>* temp2 = scheme.decrypt(secretKey, result);
        cout << temp2[0].real() << endl;
        cout << endl;
        for(int d = 2; d < coeff_list[c].size(); d++){
            cout << "Run number c = " << c << " d = " << d << endl;
            if(sq_sum1.logq > result.logq){
                scheme.modDownByAndEqual(sq_sum1, sq_sum1.logq - result.logq);
            }
            else if(sq_sum1.logq < result.logq){
                scheme.modDownByAndEqual(result, result.logq - sq_sum1.logq);
            }
            // cout << "sq.logp = " << sq_sum1.logp << "sq.logq = " << sq_sum1.logq << endl;
            // cout << "res.logp = " << result.logp << "res.logq = " << result.logq << endl;
            scheme.multAndEqual(result, sq_sum1);
            complex<double>* temp3 = scheme.decrypt(secretKey, result);
            cout << temp3[0].real() << endl;
            // cout << "After mul " << "res.logp = " << result.logp << "res.logq = " << result.logq << endl;
            scheme.reScaleByAndEqual(result, result.logp - logp);
            cout << "After rescale "<<"res.logp = " << result.logp << "res.logq = " << result.logq << endl;
            cout << "coeff.logp = " << coeff_list[c][d].logp << "coeff.logq = " << coeff_list[c][d].logq << endl;
            scheme.modDownByAndEqual(coeff_list[c][d], coeff_list[c][d].logq - result.logq);
            // cout << "coeff.logp = " << coeff_list[c][d].logp << "coeff.logq = " << coeff_list[c][d].logq << endl;
            // cout << "res.logp = " << result.logp << "res.logq = " << result.logq << endl;
            scheme.addAndEqual(result, coeff_list[c][d]);
            complex<double>* temp4 = scheme.decrypt(secretKey, result);
            cout << temp4[0].real() << endl;
            cout << endl;
        }
        // scheme.modDownByAndEqual(sq_sum1, sq_sum1.logq - result.logq);
        sq_sum1.copy(result);
        result.free();
        cout << endl;
    }
    
    // invSqRoot(sq_sum1, coeff_list, secretKey, scheme, logp);
    

    scheme.multByConstAndEqual(sq_sum2, double(1.0/64.0), sq_sum2.logp);
    cout << sq_sum2.logp << " " << sq_sum2.logq << endl;
    scheme.reScaleByAndEqual(sq_sum2, sq_sum2.logp - logp);
    cout << sq_sum2.logp << " " << sq_sum2.logq << endl;
    
    
    Ciphertext result2;
    for(int c = 0; c < coeff_list.size(); c++){
        cout << "Run number = " << c << endl;
        scheme.modDownByAndEqual(coeff_list[c][0], coeff_list[c][0].logq - sq_sum2.logq);
        // cout << "coeff.logp = " << coeff_list[c][0].logp << "coeff.logq = " << coeff_list[c][0].logq << endl;
        // cout << "sq.logp = " << sq_sum2.logp << "sq.logq = " << sq_sum2.logq << endl;
        scheme.mult(result2, sq_sum2, coeff_list[c][0]);
        complex<double>* temp = scheme.decrypt(secretKey, result2);
        cout << temp[0].real() << endl;
        // cout << "After mul " << "res.logp = " << result.logp << "res.logq = " << result.logq << endl;
        scheme.reScaleByAndEqual(result2, result2.logp - logp);
        // cout << "After rescale " << "res.logp = " << result.logp << "res.logq = " << result.logq << endl;
        scheme.modDownByAndEqual(coeff_list[c][1], coeff_list[c][1].logq - result2.logq);
        // cout << "coeff.logp = " << coeff_list[c][1].logp << "coeff.logq = " << coeff_list[c][1].logq << endl;
        // cout << "res.logp = " << result.logp << "res.logq = " << result.logq << endl;
        scheme.addAndEqual(result2, coeff_list[c][1]);
        complex<double>* temp2 = scheme.decrypt(secretKey, result2);
        cout << temp2[0].real() << endl;
        cout << endl;
        for(int d = 2; d < coeff_list[c].size(); d++){
            cout << "Run number c = " << c << " d = " << d << endl;
            if(sq_sum2.logq > result2.logq){
                scheme.modDownByAndEqual(sq_sum2, sq_sum2.logq - result2.logq);
            }
            else if(sq_sum2.logq < result2.logq){
                scheme.modDownByAndEqual(result2, result2.logq - sq_sum2.logq);
            }
            // cout << "sq.logp = " << sq_sum1.logp << "sq.logq = " << sq_sum1.logq << endl;
            // cout << "res.logp = " << result.logp << "res.logq = " << result.logq << endl;
            scheme.multAndEqual(result2, sq_sum2);
            complex<double>* temp3 = scheme.decrypt(secretKey, result2);
            cout << temp3[0].real() << endl;
            // cout << "After mul " << "res.logp = " << result.logp << "res.logq = " << result.logq << endl;
            scheme.reScaleByAndEqual(result2, result2.logp - logp);
            cout << "After rescale "<<"res.logp = " << result2.logp << "res.logq = " << result2.logq << endl;
            cout << "coeff.logp = " << coeff_list[c][d].logp << "coeff.logq = " << coeff_list[c][d].logq << endl;
            scheme.modDownByAndEqual(coeff_list[c][d], coeff_list[c][d].logq - result2.logq);
            // cout << "coeff.logp = " << coeff_list[c][d].logp << "coeff.logq = " << coeff_list[c][d].logq << endl;
            // cout << "res.logp = " << result.logp << "res.logq = " << result.logq << endl;
            scheme.addAndEqual(result2, coeff_list[c][d]);
            complex<double>* temp4 = scheme.decrypt(secretKey, result2);
            cout << temp4[0].real() << endl;
            cout << endl;
        }
        // scheme.modDownByAndEqual(sq_sum1, sq_sum1.logq - result.logq);
        sq_sum2.copy(result2);
        result.free();
        cout << endl;
    }

    scheme.reScaleByAndEqual(sum_cipher, sum_cipher.logp - logp);
    scheme.modDownByAndEqual(sum_cipher, sum_cipher.logq - sq_sum1.logq);

    scheme.multAndEqual(sum_cipher, sq_sum1);
    scheme.reScaleByAndEqual(sum_cipher, sum_cipher.logp - logp);
    scheme.modDownByAndEqual(sq_sum2, sq_sum2.logq - sum_cipher.logq);
    scheme.multAndEqual(sum_cipher, sq_sum2);
    cout << "Sum : " << sum_cipher.logp << " " << sum_cipher.logq << endl;
    cout << "Sq1 : " << sq_sum1.logp << " " << sq_sum1.logq << endl;
    cout << "Sq2 : " << sq_sum2.logp << " " << sq_sum2.logq << endl;
    complex<double>* true_val = new complex<double>[n];
    complex<double> temp = complex<double>(0.0, 0.0);
    for (long i = 0; i < n; i++) {
        temp += pow(test1[i],2);
    }
    true_val[0] = sqrt(64.0/temp);

    // for (long i = 0; i < n; i++) {
    //     true_val[i] = log(test1[i]);
    // }
    complex<double>* decrypt_p = scheme.decrypt(secretKey, sq_sum1);

    StringUtils::compare(true_val, decrypt_p, n, "prod");

    
}