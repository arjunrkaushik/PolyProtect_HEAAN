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
struct Parameters {
    long logp;
    long logq;
    long n;
};

void sum(Ciphertext &res, Ciphertext &x, Scheme &scheme, SecretKey &secretKey, Parameters params) {
    res.copy(x);
    //perform sum of all elements in Prod
    for (long j = params.n-1; j > 0; j--){
        scheme.leftRotateFastAndEqual(x, 1);
        scheme.addAndEqual(res, x);
    }
}

void inv_root(Ciphertext &result, Ciphertext &x, Scheme &scheme, SecretKey &secretKey, Parameters params) {
    complex<double>* temp = new complex<double>[params.n];
    for (int i = 0; i < params.n; i++){
        temp[i] = complex<double>(0.0, 0.0);
    }
    // Ciphertext result;
    scheme.encrypt(result, temp, params.n, params.logp, params.logq);
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
        scheme.multByConst(x1, power_x, coeff[power-1], params.logp);
        
        scheme.reScaleByAndEqual(x1, x1.logp - params.logp);

        scheme.modDownByAndEqual(result, result.logq - x1.logq);
        scheme.addAndEqual(result, x1);

        if(power > 1) {
            scheme.modDownByAndEqual(x, x.logq - power_x.logq);
        }
        if(power < 6){
            scheme.multAndEqual(power_x, x);
            scheme.reScaleByAndEqual(power_x, power_x.logp - params.logp);
        }
        
        x1.free();
        power++;
    }

    scheme.addConstAndEqual(result, g, params.logp);

    // return result;
}
void dotProduct(Ciphertext &res, Ciphertext &x, Ciphertext &y, Scheme &scheme, SecretKey &secretKey, Parameters params){
    if (x.logp > params.logp) {
        scheme.reScaleByAndEqual(x, x.logp - params.logp);
    }
    if (y.logp > params.logp) {
        scheme.reScaleByAndEqual(y, y.logp - params.logp);
    }

    if (x.logq > y.logq) {
        scheme.modDownByAndEqual(x, x.logq - y.logq);
    }
    else if (x.logq < y.logq) {
        scheme.modDownByAndEqual(y, y.logq - x.logq);
    }
    Ciphertext prod;
    scheme.mult(prod, x, y);
    scheme.reScaleByAndEqual(prod, prod.logp - params.logp);

    // Sum of elements
    sum(res, prod, scheme, secretKey, params);
}

int main() {

    long logq = 800; ///< Ciphertext Modulus
	long logp = 30; ///< Real message will be quantized by multiplying 2^40
	long logn = 7; ///< log2(The number of slots)

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

    vector<double> V = {
        -0.27108312904911624, -0.18738464736219598, 0.25770243537143545, -0.16022273290574754, 
        -0.11780624092050383, 0.5128418056607714, 0.4448151345590776, -0.1624429172676975, 
        0.3882871311131616, -0.11945387515133049, -0.011188320956991949, -0.2215422393675878, 
        0.2890864057035536, 0.2281897243775491, 0.20732738086169356, -0.010698785723157696, 
        -0.021789765531094435, -0.19480990246857177, 0.27009143096396937, -0.09575769702140435, 
        -0.16701211626770646, -0.1236817860497661, 0.027444949420916014, 0.09307139872202036, 
        0.010988112588055897, 0.2620124754400319, -0.025118229118448077, -0.21995631937490054, 
        0.4332927797125292, -0.14547698477425225, 0.29421823934016805, -0.42590281055493, 
        -0.035732369970249075, -0.23376092073313035, 0.07788514693915803, 0.2354481038236395, 
        -0.2850863104960805, 0.11280505384802342, -0.035459569174715856, -0.3510921791483883, 
        0.010424125390571526, 0.692018261960829, -0.1789115551249672, -0.09088765034656439, 
        -0.15147463444715237, -0.08876726931128087, 0.09678703958432469, -0.44744626838633694, 
        0.017310231086945915, 0.04788290093897066, 0.22317052279668434, 0.16805312318487364, 
        -0.16245353339701096, 0.17612044817162129, -0.14283142764198598, 0.08558608025889583, 
        0.03895373022985963, 0.13345783920079593, -0.03553507370152648, 0.20654482461496834, 
        -0.10944915058175946, 0.09401078090875112, -0.10032784492467625, 0.017744533989652776, 
        0.017371296751693695, -0.22798866034172743, 0.0374027400213749, 0.2678113405084524, 
        0.32025256116041245, -0.3378787644274534, -0.028363367746101653, 0.1661550628582435, 
        -0.035447664211584656, 0.09852576228047635, 0.023018626839190204, 0.34580385285044224, 
        0.16310030674119877, -0.23718203536313143, 0.09834327319183273, -0.06330002971380064, 
        -0.017965215922213056, -0.012525843914980538, -0.028910871176366253, -0.11177011056846647, 
        -0.0367250650188648, 0.18342892426273472, 0.17819565753799227, 0.555554031824194, 
        0.09170684842364236, -0.19728328371256493, -0.24906364264404857, 0.16448465718426805, 
        0.19110238760387094, -0.0009708960989297018, 0.39155978860097207, 0.1814959070807871, 
        -0.060636051376053955, -0.14499985496415968, 0.09679212762542826, 0.021707539058947848, 
        0.14618391042425297, -0.28908790052531647, 0.048015976452301164, -0.11897269076960498, 
        0.1948917887410957, 0.11669048868839298, 0.13918983072272972, 0.012079753170563813, 
        0.34037105485627384, 0.3572966070774852, -0.1886835420624386, 0.15968569454940884, 
        0.1766965416577106, 0.08197835737550208, -0.1054357783614013, -0.17764028560774725, 
        -0.2514904889986499, -0.42329887132333155, 0.008515414298385652, -0.0752087374666836, 
        -0.33580746882440016, 0.1359309876679594, -0.12804533533429152, -0.14457132042587867, 
        -0.16426500685684145, 0.2344207304710309, -0.23882297439899372, 0.31056860594437175};

    complex<double>* test1 = new complex<double>[n];    
    complex<double>* test2 = new complex<double>[n];
    complex<double>* zero = new complex<double>[n];
    
    for (long i = 0; i < n; i++){
        test1[i] = complex<double>(V[i], 0.0);
        test2[i] = complex<double>(V[i], 0.0);
        zero[i] = complex<double>(1.0, 0.0);
    }

    Parameters params = {logp, logq, n};
    Ciphertext x, y, result;
    scheme.encrypt(x, test1, n, logp, logq);
    scheme.encrypt(y, test2, n, logp, logq);

    // Calculating numerator
    // Ciphertext num;
    // scheme.mult(num, x, y);
    // scheme.reScaleByAndEqual(num, num.logp - logp);

    // // Sum of elements
    // Ciphertext num_sum;
    // sum(num_sum, num, scheme, secretKey, params);

    Ciphertext num_sum;
    dotProduct(num_sum, x, y, scheme, secretKey, params);

    //Calculating denomiator
    Ciphertext x_sq, y_sq;
    algo.powerOf2(x_sq, x, logp, 1);
    algo.powerOf2(y_sq, y, logp, 1);

    Ciphertext x_sq_sum, y_sq_sum;
    sum(x_sq_sum, x_sq, scheme, secretKey, params);
    sum(y_sq_sum, y_sq, scheme, secretKey, params);


    scheme.multByConstAndEqual(num_sum, 1.0/16.0, logp);
    scheme.reScaleByAndEqual(num_sum, num_sum.logp - logp);

    scheme.multByConstAndEqual(x_sq_sum, 1.0/16.0, logp);
    scheme.reScaleByAndEqual(x_sq_sum, x_sq_sum.logp - logp);


    scheme.multByConstAndEqual(y_sq_sum, 1.0/16.0, logp);
    scheme.reScaleByAndEqual(y_sq_sum, y_sq_sum.logp - logp);

    Ciphertext inv_root_x, inv_root_y;
    inv_root(inv_root_x, x_sq_sum, scheme, secretKey, params);
    inv_root(inv_root_y, y_sq_sum, scheme, secretKey, params);

    // cout << inv_root_x.logp << " " << inv_root_x.logq << endl;
    // cout << inv_root_y.logp << " " << inv_root_y.logq << endl;
    // cout << num_sum.logp << " " << num_sum.logq << endl;
    if(num_sum.logp > logp){
        scheme.reScaleByAndEqual(num_sum, num_sum.logp - logp);
    }

    if(num_sum.logq > inv_root_x.logq) {
        scheme.modDownByAndEqual(num_sum, num_sum.logq - inv_root_x.logq);
    }
    else if(num_sum.logq < inv_root_x.logq) {
        scheme.modDownByAndEqual(inv_root_x, inv_root_x.logq - num_sum.logq);
    }
    // cout << inv_root_x.logp << " " << inv_root_x.logq << endl;
    // cout << inv_root_y.logp << " " << inv_root_y.logq << endl;
    // cout << num_sum.logp << " " << num_sum.logq << endl;
    scheme.multAndEqual(num_sum, inv_root_x);
    scheme.reScaleByAndEqual(num_sum, num_sum.logp - logp);

    if(num_sum.logq > inv_root_y.logq) {
        scheme.modDownByAndEqual(num_sum, num_sum.logq - inv_root_y.logq);
    }
    else if(num_sum.logq < inv_root_y.logq) {
        scheme.modDownByAndEqual(inv_root_y, inv_root_y.logq - num_sum.logq);
    }

    scheme.multAndEqual(num_sum, inv_root_y);
    scheme.reScaleByAndEqual(num_sum, num_sum.logp - logp);

    complex<double>* decrypt_p = scheme.decrypt(secretKey, num_sum);

    StringUtils::compare(zero, decrypt_p, n, "prod");

    
}