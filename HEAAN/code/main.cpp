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

vector<long> generate_C(long C_range, long m) {
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

vector<long> generate_E(long m) {
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

int main() {

    //size = 1 x 512
    vector<double> embeddings{
         3.1946e-04,  1.4316e-02, -9.2333e-04,  9.9044e-03,  1.1071e-01,
         1.9806e-02, -5.0708e-04, -1.1563e-02,  3.3232e-02,  6.1914e-03,
         1.8992e-02,  4.1233e-02, -3.3673e-02,  4.2004e-02, -3.4065e-02,
         6.4882e-03, -6.0030e-02, -5.5353e-02, -1.1975e-02,  6.1748e-02,
         9.6589e-04,  3.1884e-02, -5.1511e-02, -4.8032e-02, -2.2573e-02,
         5.2869e-03,  1.6504e-02,  8.1485e-03, -3.3902e-02, -5.4159e-03,
        -1.6654e-02, -8.1413e-02, -3.6902e-03,  2.2104e-02, -1.8552e-02,
         5.6949e-03,  4.4777e-02, -1.1145e-02,  4.6340e-02, -1.2731e-02,
        -7.4652e-03,  7.9765e-02,  1.4272e-02, -3.9255e-03, -1.6277e-02,
         3.4834e-02, -1.1348e-02,  1.3206e-02, -1.2242e-03, -3.0144e-02,
         3.0278e-02, -3.1782e-02, -2.1976e-02, -6.4775e-02, -5.3453e-02,
        -3.4366e-03, -5.8664e-02, -6.6061e-03, -5.8662e-02, -4.6878e-02,
         1.7968e-02,  5.5469e-03, -2.0039e-02, -3.4274e-02, -6.2470e-02,
        -2.8524e-02, -9.5864e-03,  2.0355e-02,  3.0038e-02,  3.4124e-03,
        -1.3065e-02,  2.4636e-03, -3.0718e-03, -1.7291e-02,  4.1503e-02,
        -5.1292e-02,  2.6363e-02,  1.1578e-02,  3.0169e-03,  1.6810e-02,
        -3.3432e-02,  2.3480e-02,  4.0172e-03, -1.3027e-02,  9.8447e-03,
         6.6226e-03,  4.9400e-02, -6.1055e-02, -6.7336e-02,  4.7930e-02,
         6.8909e-03, -1.8359e-02,  2.2775e-02, -1.5362e-02, -7.5412e-03,
        -1.8815e-03,  1.1701e-01,  5.7839e-02,  2.4917e-02, -3.8062e-02,
        -4.1617e-03,  1.0115e-01,  3.0584e-02,  1.4537e-02,  2.5043e-02,
        -7.8671e-02, -2.0548e-02,  8.4013e-02,  6.4170e-02, -1.9889e-02,
         1.1555e-01, -2.7439e-02,  2.9339e-02,  2.0659e-02,  8.6353e-02,
         2.8624e-03,  7.0371e-02,  2.9324e-03,  8.4899e-02, -4.4047e-02,
         4.5884e-03,  5.8821e-02, -3.0586e-04, -6.8763e-03,  4.0111e-02,
        -3.3145e-02,  1.3777e-03,  1.2433e-02, -3.8152e-02,  2.8779e-02,
        -2.0848e-02,  7.9438e-02, -1.8000e-03, -1.5808e-02, -3.3815e-02,
        -5.7539e-02,  2.2727e-02,  4.0466e-02,  1.1451e-02,  8.6894e-02,
         3.5197e-02, -1.1844e-02, -3.9204e-02,  4.8960e-02,  4.5100e-02,
        -5.7207e-02, -3.1672e-02,  1.3074e-02,  2.1340e-03, -5.3746e-02,
        -8.9312e-03, -2.5644e-02, -5.7836e-03, -1.2279e-02,  1.1445e-02,
         7.7792e-03,  1.0715e-01,  2.9261e-02, -4.0436e-02,  4.4406e-02,
         1.1770e-02,  6.6014e-03, -1.9816e-03, -7.1418e-02,  2.2997e-02,
         4.4027e-02,  4.8339e-02, -3.3554e-03, -3.1077e-02,  5.3631e-02,
         3.8582e-02,  4.0409e-02,  1.2964e-02, -9.9999e-03,  1.1474e-01,
        -1.2591e-02, -7.4141e-03, -5.9022e-02,  2.3646e-02,  8.8833e-02,
         3.4721e-02,  2.2359e-03, -8.3562e-02, -2.0073e-02, -9.2119e-03,
         5.0335e-02, -5.7053e-02,  8.3700e-03,  3.6960e-02,  6.1517e-02,
        -2.3630e-02, -7.4994e-02, -3.9365e-02, -3.7789e-02,  7.9782e-02,
        -1.5791e-02,  1.8646e-02,  7.7585e-02,  1.2813e-02,  2.4200e-02,
        -2.9159e-02, -1.0367e-01, -5.4619e-02, -1.5690e-02,  2.8762e-02,
         7.6209e-02, -6.7189e-03, -7.2978e-03,  3.2563e-02,  1.2014e-02,
        -3.4410e-02, -8.8310e-02,  8.0961e-02, -1.0443e-01,  5.3108e-02,
         2.0054e-02, -7.8695e-02,  2.4891e-02,  3.4548e-02, -1.0859e-01,
        -5.4964e-02, -5.7034e-02,  1.8338e-02, -2.2437e-02,  5.4800e-02,
         5.8549e-02,  2.1291e-02, -2.6742e-03,  9.3013e-02,  1.0926e-02,
         1.3302e-02,  5.1911e-03, -3.3951e-02,  2.7124e-02,  5.8210e-02,
        -3.0634e-02, -5.5826e-02, -1.0046e-01,  1.4925e-02,  7.6612e-02,
         4.5984e-02, -8.3086e-03,  3.4590e-02, -3.3587e-02,  3.4571e-02,
        -1.7318e-03,  6.7946e-03,  2.3019e-02, -3.6899e-02, -3.7870e-03,
         5.4095e-03,  2.6361e-02, -2.9154e-03, -5.2745e-02,  1.1797e-01,
        -2.0051e-02, -1.9654e-02,  1.2298e-02,  1.1438e-02, -4.0144e-02,
        -9.6831e-02,  6.7332e-02, -2.0158e-02, -1.8311e-02,  2.7102e-02,
         6.2025e-02,  4.1771e-02, -2.4057e-03,  3.3104e-02,  3.9002e-03,
        -6.7338e-02,  4.6523e-02, -2.1378e-02, -1.0365e-02,  1.6505e-02,
        -1.2640e-02,  6.1127e-02,  3.0728e-02, -4.3444e-03, -8.8525e-02,
         8.4482e-03,  6.7798e-02,  1.1147e-01,  2.4220e-02, -1.7983e-02,
        -6.8263e-02, -2.9747e-03,  2.3392e-02,  1.0600e-02,  5.3460e-02,
        -3.9002e-02, -6.7294e-02, -5.6929e-02,  4.3350e-03,  8.1036e-03,
         1.3950e-02, -5.5138e-02,  3.4373e-02, -4.0158e-02, -3.7856e-02,
        -2.6392e-03,  4.7603e-02, -6.4612e-02,  5.9631e-02, -5.4136e-02,
         1.1809e-02, -5.8774e-02, -3.6512e-02, -1.0882e-02,  2.1480e-02,
         4.1525e-02,  1.2604e-02,  6.7448e-03, -6.4988e-03,  2.8622e-02,
        -7.4653e-02,  6.9989e-03,  2.8686e-02, -2.2905e-02,  6.2123e-02,
         1.9438e-02,  1.0370e-01, -3.7863e-02, -2.1643e-02, -9.8416e-03,
         1.7660e-02,  1.9300e-02, -9.9197e-03,  5.5199e-03, -5.7405e-02,
        -2.8118e-02, -5.1137e-02,  4.5083e-02,  6.5105e-02, -4.2595e-03,
        -7.0263e-02,  1.9793e-02, -2.6846e-02,  3.6405e-02, -3.2393e-03,
         9.4253e-02,  3.5984e-02,  3.9591e-02,  2.3997e-02, -4.7983e-02,
         2.7134e-02, -2.8917e-02, -8.7614e-02, -3.2709e-02, -1.0696e-01,
        -6.6373e-02, -1.3607e-02,  4.4390e-02,  5.4915e-03,  3.9493e-02,
        -7.8231e-02, -2.4292e-03, -1.5169e-02, -4.4705e-02, -7.9192e-03,
         5.3030e-02, -9.2902e-03,  2.5091e-02, -4.5183e-03, -3.6469e-02,
        -6.9400e-02, -4.7218e-02, -6.5490e-02,  1.1106e-02, -3.3299e-02,
        -2.1941e-02, -3.0466e-02, -1.4528e-02, -2.6883e-02, -3.1652e-03,
        -2.9890e-02, -3.9503e-02,  4.0310e-02,  1.5597e-02,  7.7536e-02,
        -2.0338e-02, -6.0909e-02, -5.5435e-02,  9.1274e-03,  2.8295e-03,
         2.1530e-02,  1.4948e-02,  4.3478e-02,  6.0577e-02,  4.3628e-02,
        -2.2235e-02,  6.8044e-02,  1.8539e-02,  1.8253e-02, -4.2879e-02,
         9.5840e-02,  7.1565e-02, -1.6856e-02,  5.8630e-02,  7.5819e-03,
         2.1569e-02, -1.4998e-02, -1.0920e-02, -7.4900e-02,  3.5128e-02,
         4.1055e-02, -9.0625e-02, -3.7211e-03,  9.9234e-03, -3.1686e-02,
         2.3684e-02, -7.5992e-03,  3.1312e-02,  2.6860e-03, -2.1168e-02,
        -5.1231e-02, -9.8450e-03,  2.8805e-02,  1.5280e-02, -3.9778e-02,
         1.2051e-02, -3.0592e-02, -8.6315e-03, -8.7091e-02,  9.4652e-03,
         2.0318e-02, -5.9195e-02, -4.4589e-02, -3.3700e-02,  5.3901e-03,
         5.2849e-02, -9.3260e-03, -3.6745e-02,  6.5854e-02, -2.0916e-03,
        -5.3096e-02,  4.4652e-03,  5.2541e-02, -3.1714e-02,  1.2011e-02,
         2.6174e-02,  4.3884e-02, -6.4220e-03,  2.4565e-02, -6.0957e-02,
         1.3897e-02, -6.2234e-02, -4.2479e-02,  1.2465e-01, -7.9923e-02,
         2.0180e-02, -3.9039e-02, -2.1897e-02,  4.8287e-02,  1.2608e-03,
        -2.4273e-02,  4.0413e-02, -6.9116e-02,  1.4132e-02, -4.4331e-02,
         8.6349e-02, -5.3900e-02, -3.3245e-03, -8.1427e-02, -1.3970e-02,
        -5.8743e-03,  7.6996e-03,  2.3893e-02, -2.8343e-02,  1.5726e-03,
        -3.9882e-02, -6.1838e-05, -2.9210e-02, -7.5353e-02, -3.0373e-02,
         1.2662e-02,  5.4526e-02, -4.8721e-02, -6.5579e-04, -1.7839e-02,
        -4.9017e-02,  1.4411e-01, -2.6555e-02, -2.9778e-02,  1.9027e-02,
        -3.3150e-03,  2.8658e-02, -1.5656e-02, -9.8843e-03,  1.3649e-03,
         3.7422e-02,  5.4432e-02, -4.0671e-03,  8.8250e-02,  2.4207e-02,
         1.0000e-01, -5.8957e-02, -2.7789e-02,  4.4180e-02,  3.9576e-02,
         1.8114e-02,  8.6596e-02,  2.8693e-04, -8.8548e-02,  7.2972e-02,
        -2.2716e-02,  6.0052e-02, -6.8119e-02, -1.1225e-03, -7.1398e-03,
         7.3155e-02,  3.7297e-02
    };

    
    // double* embeddings = embeddings_array;

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

    // Ciphertext embeddings_cipher;

    // scheme.encrypt(embeddings_cipher, embeddings, n, logp, logq);
    // absolute min/max values of the coefficients range 
    timeutils.start("Begin P");
    long C_range = 50;
    // Number of coefficients and exponents used in the PolyProtect mapping. Should be only a power of 2.
    long m = 4;   
    long overlap = 0;
    long step_size = m - overlap;

    long remainder = n % step_size;
    long padding;
    if (remainder > 0) {
        padding = (step_size - remainder) % step_size;
    }
    else {
        padding = 0;
    }

    embeddings.resize(embeddings.size() + padding, 0.0);

    complex<double>* embeddings_new = new complex<double>[embeddings.size()];
    for (long i = 0; i < embeddings.size(); i++) {
        embeddings_new[i] = complex<double>(embeddings[i], 0.0);
    }

    cout << "Resizing done" << endl;
    vector<Ciphertext> embeddings_ciphers;
    for (long i = 0; i < embeddings.size(); i+= step_size) {
        Ciphertext word_cipher;
        complex<double>* word_array = new complex<double>[m];
        for (long j = 0; j < m; j++){
            word_array[j] = embeddings_new[i+j];
        }
        // double* word_ptr = word_array;
        scheme.encrypt(word_cipher, word_array, m, logp, logq);
        embeddings_ciphers.push_back(word_cipher);
        word_cipher.free();
    }


    cout << "Embeddings encrypted" << endl;

    vector<long> C = generate_C(C_range, m);
    vector<long> E = generate_E(m);

    cout << "C,E gen" << endl;

    

    cout << "Entering P creation" << endl;
    vector<Ciphertext> P;
    int cnt = 0;
    for (auto i : embeddings_ciphers) {
        cout << cnt << endl;
        complex<double>* v0 = new complex<double>[m];
        for (long i = 0; i < m; i++) {
            v0[i] = complex<double>(0.0,0.0);
        }
        Ciphertext temp_p;
        scheme.encrypt(temp_p, v0, m ,logp, logq);

        for (long j = 0; j < m; j++) {
            // cout << "j = " << j << endl;
            // cout << "E[j] = " << E[j] << endl;
            complex<double>* temp = new complex<double>[m];
            for (long k = 0; k < m; k++) {
                temp[k] = complex<double>(0.0,0.0);
            }
            temp[j] = complex<double>(1.0, 0.0);

            // double* temp_ptr = temp;
            
            Ciphertext temp_word, res;
            scheme.encrypt(temp_word, temp, m, logp, logq);
            // cout << temp_word.logp << temp_word.logq << endl;
            // cout << i.logp << i.logq << endl;
            scheme.multAndEqual(temp_word, i);
            // cout << temp_word.logp << temp_word.logq << endl;
            algo.power(res, temp_word, logp, E[j]);
            // cout << res.logp << res.logq << endl;
            // scheme.reScaleToAndEqual(res, res.logq - abs(logq - res.logq));
            // scheme.reScaleToAndEqual(res, res.logq);
            // cout << res.logp << res.logq << endl;
            scheme.multByConstAndEqual(res, C[j], logp);
            // cout << res.logp << res.logq << endl;
            scheme.reScaleByAndEqual(res, res.logp - logp);
            // cout << res.logp << res.logq << endl;
            // cout << temp_p.logp << temp_p.logq << endl;
            if (temp_p.logq > res.logq) {
                scheme.modDownToAndEqual(temp_p, res.logq);
            }
            else if (temp_p.logq < res.logq){
                scheme.modDownToAndEqual(res, temp_p.logq);
            }
            // cout << res.logp << res.logq << endl;
            // cout << temp_p.logp << temp_p.logq << endl;
            scheme.addAndEqual(temp_p, res);
            // cout << temp_p.logp << temp_p.logq << endl;

            

            temp_word.free();
            res.free();
            delete[] temp;
            // break;
        }

        Ciphertext temp_sum_cipher;
        temp_sum_cipher.copy(temp_p);
        temp_sum_cipher.logp = temp_p.logp;
        temp_sum_cipher.logq = temp_p.logq;
        //perform sum of all elements in P
        for (long j = m; j > 0; j--){
            // cout << "Round " << j << endl;
            // temp_sum_cipher = temp_p;
            // cout << temp_p.logp << temp_p.logq << endl;
            // cout << temp_sum_cipher.logp << temp_sum_cipher.logq << endl;
            scheme.leftRotateFastAndEqual(temp_p, 1);
            // cout << temp_sum_cipher.logp << temp_sum_cipher.logq << endl;
            scheme.addAndEqual(temp_sum_cipher, temp_p);
            // cout << temp_sum_cipher.logp << temp_sum_cipher.logq << endl;
            // cout << temp_sum_cipher.logp << temp_sum_cipher.logq << endl;
        }

        // complex<double>* true_val = new complex<double>[m];
        // for (long k = 0; k < m; k++) {
        //     true_val[k] = complex<double>(0.0,0.0);
        // }
        // double true_temp = 0.0;
        // for (long k = 0; k < m; k++) {
        //     true_temp += C[k]*pow(embeddings[k], E[k]);
        // }
        // true_val[0] = complex<double>(true_temp, 0.0);

        // complex<double>* decrypt_p = scheme.decrypt(secretKey, temp_sum_cipher);

        // StringUtils::compare(true_val, decrypt_p, m, "P");
        // break;
        P.push_back(temp_sum_cipher);
        temp_sum_cipher.free();
        delete[] v0;
        cnt++;
        
    }

    timeutils.stop("End P");
    
}