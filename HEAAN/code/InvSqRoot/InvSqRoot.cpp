#include "InvSqRoot.h"

#include <iterator>
#include <fstream>
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

using namespace NTL;
using namespace std;

// Zero finding
// y1 = y*(1 + 3*x*pow(y,2)) / ( 1 + x*pow(y,2))
Ciphertext InvSqRoot::ZeroFinding(Ciphertext x, int length, int depth, SecretKey &secretKey, Scheme &scheme, long logp, long logq) {
    complex<double>* val_y = new complex<double>[length];    
    
    for (long i = 0; i < length; i++){
        val_y[i] = complex<double>(1.0, 0.0);
    }
    
    Ciphertext y;
    scheme.encrypt(y, val_y, length, logp, logq);
    
    int cnt = depth;    //Decides acccuracy. cnt >=5 yields max accuracy

    while(cnt > 0){
        // cout << cnt << endl;
        Ciphertext k, temp, y_squared, sum_num, sum_denom, denom_inv;
        algo.powerOf2(y_squared, y, logp, 1);
        // cout << y.logq << " "  << y.logp << endl;
        // cout << "y^2 = " << y_squared.logq << " "  << y_squared.logp << endl;
        if(x.logq > y_squared.logq){
            scheme.modDownByAndEqual(x, x.logq - y_squared.logq);
        }
        else if(x.logq < y_squared.logq){
            scheme.modDownByAndEqual(y_squared, y_squared.logq - x.logq);
        }
        scheme.mult(temp, x, y_squared);
        // cout << "x = " << x.logq << " "  << x.logp << endl;
        // cout << "y^2 = " << y_squared.logq << " "  << y_squared.logp << endl;
        scheme.reScaleByAndEqual(temp, temp.logp - logp);
        // cout << "k = " << k.logq << " "  << k.logp << endl;
        

        scheme.addConst(sum_num, temp, 3.0, temp.logp);
        scheme.addConst(sum_denom, temp, 1.0, temp.logp);

        // cout << "Added" << endl;        
        // cout << "Num = " << sum_num.logq << " "  << sum_num.logp << endl;
        // cout << "Denom = " << sum_denom.logq << " "  << sum_denom.logp << endl;
        scheme.multAndEqual(sum_num, y);
        scheme.reScaleByAndEqual(sum_num, sum_num.logp - logp);

        // cout << "Mult with y" << endl;        
        // cout << "Num = " << sum_num.logq << " "  << sum_num.logp << endl;
        scheme.multByConstAndEqual(sum_num, 1.0/32.0, sum_num.logp);
        scheme.reScaleByAndEqual(sum_num, sum_num.logp - logp);
        // cout << "Normalized Num" << endl;
        // cout << "Num = " << sum_num.logq << " "  << sum_num.logp << endl;
        scheme.multByConstAndEqual(sum_denom, 1.0/32.0, sum_denom.logp);
        scheme.reScaleByAndEqual(sum_denom, sum_denom.logp - logp);
        // cout << "Normalized Denom" << endl;
        // cout << "Denom = " << sum_denom.logq << " "  << sum_denom.logp << endl;
        algo.inverse(denom_inv, sum_denom, sum_denom.logp, 8);
        // cout <<"Inversed" << endl;
        
        // cout << "Num = " << sum_num.logq << " "  << sum_num.logp << endl;
        // cout << "Denom = " << denom_inv.logq << " "  << denom_inv.logp << endl;
        if(denom_inv.logq > sum_num.logq){
            scheme.modDownByAndEqual(denom_inv, denom_inv.logq - sum_num.logq);
        }
        else if(denom_inv.logq < sum_num.logq){
            scheme.modDownByAndEqual(sum_num, sum_num.logq - denom_inv.logq);
        }

        // cout << "After mod down" << endl;
        // cout << "Num = " << sum_num.logq << " "  << sum_num.logp << endl;
        // cout << "Denom = " << denom_inv.logq << " "  << denom_inv.logp << endl;
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

    return Ciphertext;
}

// Newtons method
// y1 = y*(3 - x*pow(y,2)) / 2
Ciphertext InvSqRoot::Newtons(Ciphertext x, int length, int depth, SecretKey &secretKey, Scheme &scheme, long logp, long logq) {
    complex<double>* val_y = new complex<double>[length];    
    for (long i = 0; i < length; i++){
        val_y[i] = complex<double>(1.0, 0.0);
    }
    
    Ciphertext y;
    scheme.encrypt(y, val_y, length, logp, logq);
    
    int cnt = depth;    //Decides acccuracy. cnt >=5 yields max accuracy

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
    
    return y;
}

Ciphertext InvSqRoot::Polynomial(Ciphertext x, int length, SecretKey &secretKey, Scheme &scheme, long logp, long logq) {   
    complex<double>* zero = new complex<double>[length];
    
    for (long i = 0; i < length; i++){
        zero[i] = complex<double>(0.0, 0.0);
    }


    Ciphertext result;
    scheme.encrypt(result, zero, length, logp, logq);
    
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

    return result;
}