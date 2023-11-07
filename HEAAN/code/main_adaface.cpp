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
    vector<vector<double>> embeddings{{
         -6.5491e-02, -3.1176e-02,  9.7325e-02,  6.3672e-02, -1.3480e-02,
          2.3924e-02, -1.7355e-02,  3.7704e-02, -5.0929e-02, -4.4762e-02,
         -3.4525e-02, -4.5447e-02,  3.6149e-03, -4.3162e-02, -5.1272e-02,
          3.2919e-02, -5.6646e-02, -4.9231e-02,  5.4605e-03,  3.1172e-02,
          9.2999e-02, -6.9230e-02,  6.4920e-02, -8.1839e-02, -1.1686e-02,
          1.3734e-02, -1.8845e-02, -8.8715e-02, -6.5991e-03, -6.9363e-02,
         -6.7909e-02,  3.6049e-02,  6.2287e-02,  3.9043e-02,  1.3912e-02,
         -7.0493e-02, -2.3690e-03,  5.5246e-02, -2.4145e-02,  2.2218e-02,
         -2.4600e-02,  1.4668e-02, -1.4385e-02,  3.4167e-03, -6.2292e-02,
          4.8883e-02,  9.3155e-03,  5.0901e-02, -1.1588e-01, -1.8564e-02,
         -3.5317e-02, -3.0887e-02,  5.5744e-02, -8.1871e-02, -4.9830e-02,
         -3.3896e-02,  4.1022e-02,  5.1389e-02, -2.9675e-02, -3.9452e-02,
         -5.7576e-02,  9.2816e-03, -2.3486e-02,  8.7637e-03,  5.8983e-02,
         -1.7129e-03, -6.1576e-02,  1.1408e-02,  5.0387e-02,  7.4203e-02,
         -2.7684e-03,  3.9954e-02,  8.0819e-03,  4.3533e-02, -8.6035e-02,
         -5.4362e-02, -4.8567e-02, -3.6152e-02, -3.0390e-02,  2.4347e-02,
          2.1882e-03, -3.1298e-04,  6.8322e-04,  3.3412e-02, -2.1765e-02,
         -3.9816e-02,  4.9282e-03,  2.6315e-02, -3.9465e-03, -3.7975e-02,
         -4.4221e-03, -4.9102e-03, -6.3509e-02,  2.2760e-02,  4.7794e-02,
         -1.0632e-02,  1.4493e-02,  2.1500e-02,  6.6035e-03, -1.8769e-03,
          2.2972e-02, -5.8824e-02, -6.6691e-02, -4.9185e-02, -1.0419e-02,
         -3.5829e-02, -8.9094e-04,  5.7007e-03, -3.4215e-02,  2.7737e-03,
         -6.5053e-02,  4.6447e-02, -2.3968e-02,  7.4269e-03, -1.8330e-02,
         -8.5513e-02,  3.3880e-02, -1.1906e-02,  7.1951e-03,  3.1408e-02,
         -1.4774e-02,  2.8438e-02, -3.1232e-02, -5.8631e-02,  1.3712e-02,
          2.7847e-02, -6.6524e-02,  8.5466e-02,  3.4008e-02, -1.0200e-01,
         -2.1462e-02,  2.0073e-02, -4.0710e-02,  5.3133e-02,  1.3518e-02,
          4.8567e-02, -1.0901e-04, -4.5189e-03, -4.8387e-02, -1.5541e-02,
          1.0409e-02, -3.4963e-02, -1.2476e-01, -4.4895e-02, -1.4321e-02,
          9.4799e-02, -2.1247e-03,  4.8908e-02, -3.6433e-03, -3.2079e-03,
          2.6452e-02, -2.2531e-02, -1.0875e-02,  2.5669e-02,  2.7362e-02,
          7.1629e-03,  2.3959e-02, -8.0951e-02, -1.8350e-02,  7.6672e-02,
          1.2707e-01,  3.2736e-02,  3.1206e-02,  2.9864e-02, -2.1817e-02,
          5.6456e-02,  2.0362e-02, -1.3925e-01,  1.7918e-03, -1.9684e-02,
          2.5775e-03,  3.5865e-02,  4.8176e-02,  1.9413e-02, -2.2954e-02,
          2.2748e-02, -3.1069e-02,  5.7131e-02, -7.8110e-02,  3.0599e-02,
         -6.7000e-02,  2.6207e-02,  5.9560e-02,  2.6632e-02,  5.9877e-02,
          1.1205e-01,  1.9892e-02, -2.6254e-02,  2.1820e-02, -1.9570e-02,
         -2.2260e-02,  9.0518e-02,  3.3447e-02, -4.8561e-02, -3.7906e-02,
         -6.6278e-05, -1.4043e-02,  5.7815e-02, -4.9899e-02, -1.1075e-02,
         -2.2853e-02,  1.4009e-02,  2.0260e-02, -4.3616e-02,  7.2459e-02,
         -1.8850e-02, -3.7776e-02, -2.3030e-02,  2.9152e-02, -2.0981e-02,
         -2.4367e-02,  3.4285e-02,  2.6282e-02, -2.8255e-02, -8.2881e-03,
         -3.3617e-02,  1.3021e-02,  3.7713e-02, -4.4069e-03,  2.8369e-02,
          4.0345e-02, -2.8376e-02, -6.1117e-02, -1.3544e-02, -6.0144e-03,
          2.8797e-02, -7.8827e-02, -7.7101e-03,  3.8346e-02, -2.8743e-02,
          3.7213e-02, -2.3501e-02, -2.9615e-02, -5.8165e-02,  2.0219e-02,
          1.0830e-02, -2.6231e-02, -8.1310e-02,  8.4942e-02, -3.4224e-02,
          3.7866e-02,  8.6021e-02,  4.7911e-02,  1.8426e-02,  9.0322e-02,
          1.3551e-02,  2.5747e-02, -2.5081e-03, -4.8551e-02, -7.9538e-03,
          9.7507e-04,  2.4785e-02, -2.0910e-02, -1.3531e-02,  1.0472e-02,
         -2.6496e-03,  2.5701e-02,  2.1668e-03, -3.6190e-02, -2.1423e-03,
         -1.9639e-02,  1.0857e-02, -2.5450e-02,  4.6359e-02, -4.1954e-02,
         -4.8813e-02,  1.6122e-03, -2.7972e-03,  5.8418e-02, -3.9283e-02,
         -6.2192e-02, -4.6035e-02,  6.3595e-02, -1.9078e-02, -1.6062e-02,
         -5.5892e-02, -5.0175e-03,  9.4943e-02, -2.0908e-02,  5.9069e-02,
         -1.5467e-02,  6.6417e-03, -4.4765e-02,  6.1739e-03, -4.9068e-02,
         -4.3111e-02, -5.6109e-02, -2.7551e-02, -1.6851e-02, -3.7931e-02,
          2.5529e-02,  8.2059e-03, -2.8027e-02,  7.8230e-02, -5.4808e-02,
         -2.2864e-02,  5.6884e-03,  5.2930e-02, -1.0843e-02, -6.0218e-03,
         -6.3915e-02, -2.8444e-02,  1.5679e-02, -6.0760e-02, -1.8221e-05,
         -2.6403e-02, -2.9888e-03, -3.2436e-02,  6.1709e-04, -1.7194e-02,
          1.8795e-03,  4.7488e-02, -5.7702e-02, -3.5825e-03, -5.5824e-02,
         -1.2947e-02, -3.7390e-02, -6.1107e-02,  2.0785e-02,  1.7739e-02,
          8.1155e-05,  4.5519e-02, -5.5899e-02,  2.7124e-03,  5.3231e-03,
         -9.7925e-03,  1.7276e-02,  2.5718e-03, -6.9783e-03,  6.2661e-02,
          3.7646e-02,  3.4321e-03,  3.9320e-02, -5.1611e-02,  1.0988e-02,
          2.6821e-02, -1.4528e-02,  2.6763e-02, -2.0143e-02,  7.5765e-03,
          1.6067e-02, -3.6667e-02, -4.5942e-02, -3.5648e-02, -1.2666e-02,
          1.2116e-04, -1.4416e-02, -3.5318e-02,  2.6814e-02,  7.2173e-02,
          2.4417e-02, -1.1343e-01, -4.4114e-03, -1.0569e-03, -5.0136e-02,
         -1.8262e-02, -1.5357e-03,  7.8114e-02, -6.8509e-02,  3.4836e-02,
         -3.7827e-02, -7.5237e-02,  5.0504e-02,  5.6975e-02, -1.0624e-01,
          2.3435e-02, -1.8570e-02, -1.0451e-02,  9.4179e-02,  2.9534e-02,
         -6.4347e-02, -2.0629e-02,  3.5190e-02, -1.6849e-03,  3.5356e-02,
          2.6809e-03, -4.0458e-02,  6.8746e-02, -9.6291e-02, -7.7737e-02,
          3.1252e-02, -2.1317e-02,  6.6735e-02, -3.4122e-02,  3.7657e-02,
         -3.9744e-03, -9.9463e-03,  1.4964e-02, -3.0083e-02, -1.1768e-02,
          5.8656e-02,  3.0902e-02, -9.5259e-03,  6.3576e-02,  8.6640e-02,
         -2.1386e-02,  4.0646e-02, -4.3852e-02, -2.1585e-03, -1.9404e-04,
         -3.2753e-02,  9.7325e-02,  8.8651e-03, -3.6310e-02, -3.3126e-02,
         -5.9759e-02,  9.0095e-02,  6.2568e-02,  2.9636e-02,  4.1453e-02,
          7.3250e-03, -8.5589e-03, -3.0317e-02,  7.2264e-03, -2.6154e-02,
          2.5632e-02, -6.3830e-02, -8.1208e-02, -6.4147e-02, -2.5366e-02,
         -1.8331e-02, -1.1378e-01,  6.9339e-03, -7.9362e-03, -1.6629e-02,
          3.8941e-02,  7.3563e-02, -2.7688e-02,  3.0655e-02,  5.9988e-02,
         -3.5701e-02, -2.6848e-03, -1.1570e-02, -3.7452e-02, -1.2571e-02,
         -6.7281e-02,  8.8932e-02,  2.1564e-02, -2.7748e-02, -5.5738e-02,
         -7.4572e-02, -1.2264e-02, -1.0182e-01,  4.9565e-02,  1.2118e-01,
         -6.5276e-02,  2.9689e-02,  2.1840e-04, -7.7639e-03, -1.4542e-02,
          2.0455e-03, -3.5188e-02,  5.4426e-03,  1.3742e-02, -5.6962e-02,
         -1.6295e-02,  4.9724e-02,  3.3597e-02,  3.6307e-02,  2.5664e-02,
          3.1833e-03,  1.4891e-02,  6.6571e-02,  3.5641e-02,  3.3583e-02,
         -1.2858e-03, -2.4337e-02,  5.2556e-02,  4.1744e-02, -2.0947e-03,
          1.9935e-02,  8.8146e-02, -3.0061e-02,  9.6283e-03,  6.2504e-02,
          1.9300e-04,  4.7353e-03, -6.3149e-02, -4.6971e-02,  1.7636e-02,
         -1.0564e-02, -4.3194e-03, -2.8964e-02,  6.7390e-02,  5.5426e-02,
          6.0540e-02, -1.0186e-01, -2.2572e-02, -4.4663e-02, -1.3136e-02,
          3.3118e-02,  2.9629e-02, -1.4867e-02,  5.2505e-02,  1.1828e-02,
          2.7909e-02, -7.6872e-02, -3.8730e-02, -9.0873e-02,  4.5689e-02,
          4.6524e-02,  6.9340e-02, -6.0558e-02, -4.5803e-02,  3.8924e-02,
          2.9367e-02,  1.6856e-02,  5.0542e-02, -6.3030e-02,  3.4161e-03,
          5.3785e-02, -5.4115e-02},
          {-6.5083e-02, -1.0127e-02,  4.1956e-02,  8.1287e-02, -4.8565e-02,
          2.5510e-02, -3.8213e-03,  9.1188e-02, -1.4105e-02, -2.0091e-02,
         -8.0016e-02, -6.3788e-02,  7.9670e-03, -1.3891e-02, -6.0442e-02,
          3.4085e-02, -1.5411e-02, -1.0750e-01,  6.6545e-02, -1.7296e-03,
          1.9881e-02, -6.7457e-02,  5.6396e-02, -3.4500e-02, -1.1577e-02,
         -1.2422e-02, -2.8139e-02, -8.1752e-02, -2.9323e-02, -6.5379e-02,
         -2.8124e-03,  5.9420e-02,  1.0224e-01,  2.3144e-02,  2.5949e-02,
         -8.2880e-02,  5.5520e-02,  1.7938e-02, -1.2426e-02,  4.8363e-02,
         -8.2336e-03,  4.4304e-02,  1.9021e-02, -1.4503e-02, -5.1242e-02,
          3.5878e-02,  5.9983e-02,  2.4964e-02, -4.7512e-02, -3.4066e-02,
         -6.4047e-02,  1.8230e-02,  2.8195e-03, -6.3320e-02, -3.8411e-02,
         -6.2906e-03, -1.6980e-02,  1.7608e-02, -3.7679e-02, -1.6646e-02,
         -5.0935e-02,  6.9236e-02,  2.4205e-02,  3.4931e-03,  4.5487e-02,
          2.1436e-02, -1.5994e-02,  2.0639e-02,  3.8790e-02,  6.2653e-02,
         -3.6265e-03,  5.2552e-02,  3.3242e-02, -5.5062e-03, -5.2371e-03,
         -7.5844e-02, -2.4082e-02, -3.5770e-02,  2.4236e-03,  1.1704e-02,
          3.8490e-03,  3.1242e-02,  8.0793e-03,  2.9241e-02,  2.4422e-02,
         -8.4981e-02,  2.5865e-02,  2.1615e-02,  1.5171e-02, -4.7530e-02,
         -1.6327e-02, -4.9195e-02, -5.0722e-02, -1.9079e-03, -8.9568e-04,
         -3.6673e-02, -2.8119e-02,  6.7648e-02, -1.7909e-02, -9.4571e-03,
         -2.9060e-02, -1.2551e-01, -5.7226e-02, -1.9069e-02,  5.4085e-03,
         -7.6661e-03, -7.2123e-03, -2.0637e-02, -6.4040e-02,  3.1126e-03,
         -4.7629e-02,  7.8316e-03,  2.1452e-02,  5.2312e-02, -8.8564e-03,
         -6.3431e-02,  5.7627e-02, -1.7385e-02,  1.5174e-02,  9.7933e-02,
         -2.5999e-02, -2.2413e-02, -6.1308e-02, -9.0661e-02, -3.8923e-03,
         -3.0737e-03, -3.8842e-02,  1.0690e-01, -2.4366e-03, -3.8691e-03,
          5.4996e-03, -3.7966e-02,  3.0728e-03, -1.3475e-02, -2.9399e-02,
          5.2946e-02, -1.3726e-02, -6.7036e-02, -2.5865e-02, -2.0744e-02,
          2.1456e-02, -1.7362e-02, -9.1342e-02,  3.5895e-04,  2.2850e-02,
          8.8578e-02, -4.5475e-02,  2.5770e-02,  3.1617e-02,  3.3159e-03,
          7.6960e-02, -3.4548e-02, -1.1870e-02,  2.0416e-02,  6.3090e-03,
          2.9488e-02, -3.3510e-02, -5.4195e-02, -2.3149e-02,  2.2986e-02,
          1.0887e-01,  4.0877e-02,  1.6286e-03,  6.3230e-02, -2.4008e-02,
          3.5632e-02, -6.5539e-03, -7.7814e-02,  2.0213e-04, -3.8718e-02,
         -5.0825e-02,  8.6513e-02,  2.6558e-02,  8.6049e-02, -7.2140e-03,
          3.7533e-02, -6.1301e-02,  7.6988e-02, -1.0154e-01, -7.4948e-04,
         -4.9667e-02, -3.6736e-04,  5.6399e-02, -9.9794e-03,  7.6739e-02,
          8.9822e-02, -1.1953e-02, -4.8050e-02, -3.0279e-02, -1.4823e-02,
         -2.2175e-02,  7.0888e-02,  6.7563e-02, -6.0975e-02, -2.1296e-02,
          1.5652e-02,  1.0131e-02,  3.4777e-02, -1.4372e-02, -9.1299e-03,
         -4.0891e-02, -2.3772e-02, -9.1903e-04, -2.0282e-02,  5.8749e-02,
          1.7074e-02, -6.2190e-02, -2.2231e-02,  2.0525e-02, -1.5417e-02,
         -1.6026e-02,  5.1761e-02,  3.3785e-02, -4.1362e-02,  8.6126e-04,
         -3.4176e-02,  5.1803e-02, -2.0969e-05, -4.6185e-02,  3.8839e-03,
         -2.0421e-02, -6.1751e-02, -5.6156e-02,  1.7738e-02, -6.5584e-02,
          3.7892e-02, -6.0169e-02, -4.7510e-02,  5.9552e-03, -9.7951e-03,
          3.9938e-02,  5.5051e-03, -5.9442e-02, -3.4386e-02,  7.4877e-02,
         -2.6251e-02, -2.9616e-02, -7.9909e-02,  2.8242e-02, -6.2954e-03,
         -4.3485e-03,  9.5477e-02,  7.2246e-02,  1.5249e-02,  5.6296e-02,
         -1.1603e-03,  3.3368e-02,  2.6695e-02, -2.2079e-02, -3.6273e-02,
         -4.1469e-02,  1.2487e-02, -5.0551e-02,  1.9121e-02, -5.1846e-02,
          3.2933e-03, -4.1514e-02,  1.3101e-02, -5.3405e-02, -1.6143e-02,
         -1.5015e-02, -4.3915e-02, -2.2159e-02,  6.7569e-02,  2.1898e-03,
          1.8392e-02,  4.9801e-02, -1.3019e-02,  5.4893e-02, -1.6073e-02,
         -8.6486e-02, -3.3154e-02,  7.1572e-02,  4.3626e-02, -1.0682e-01,
         -7.4425e-02, -2.9662e-02,  1.0275e-01, -3.5738e-02,  2.4686e-02,
         -1.3802e-02, -5.1171e-03, -3.3499e-02, -4.8014e-03, -1.2416e-01,
          8.9415e-03, -8.6575e-02, -6.2745e-02,  1.8524e-02, -9.0315e-02,
          1.5158e-02, -1.0024e-02, -2.3177e-02, -1.9251e-02,  2.7602e-02,
          1.2582e-02, -1.6058e-02,  4.2023e-02, -2.0534e-02, -2.1255e-03,
         -6.8530e-02, -4.2171e-02, -4.7245e-02, -4.3346e-02,  1.4883e-03,
         -5.4608e-02, -2.6113e-02, -3.2574e-02,  1.8057e-02, -2.0548e-02,
         -2.0318e-02, -1.3712e-02, -2.4829e-02, -4.9036e-02, -3.5012e-02,
         -1.3268e-02, -4.2608e-02, -5.8943e-02, -3.9433e-03,  4.4757e-02,
          3.3110e-02, -2.4299e-02,  2.0946e-02,  2.2191e-03,  2.0977e-03,
         -4.2246e-02,  1.0117e-02, -3.7378e-03, -1.0289e-02,  5.8744e-02,
          4.4745e-02, -8.3707e-03,  5.6051e-02,  6.0719e-03,  6.8751e-03,
          3.6311e-02, -2.5139e-02,  8.0850e-02,  3.2958e-03,  5.4396e-03,
          2.5166e-02,  9.9300e-03, -7.0638e-03, -4.2873e-03,  1.5131e-02,
          3.2562e-03, -1.9692e-02, -7.0126e-02,  4.7488e-02,  3.7719e-02,
          5.5358e-02, -4.8727e-02, -1.8795e-02,  3.7152e-02, -4.2388e-02,
          1.4424e-02,  2.7314e-02,  5.5625e-02, -6.0600e-02,  5.1118e-02,
         -6.9900e-02, -2.7586e-02,  6.7054e-02,  1.5968e-02, -1.2541e-01,
          1.3269e-02,  1.6050e-02, -5.3249e-02,  8.6126e-02, -2.9430e-02,
         -5.9874e-02, -8.0641e-03,  1.1284e-01, -2.4585e-02, -3.0718e-02,
          6.2555e-03,  3.1208e-03, -5.8778e-03, -2.1132e-02, -4.3800e-02,
          6.7153e-03, -6.0590e-02,  5.0110e-02, -3.2914e-02,  2.4962e-02,
          2.2818e-02, -4.6940e-02,  1.0371e-02, -4.1552e-02, -6.3433e-02,
          4.8425e-02,  3.8024e-02,  4.3760e-02,  8.7268e-02,  7.0188e-02,
          1.1030e-02,  7.0130e-02, -1.7223e-02,  6.3961e-03,  5.3374e-02,
         -6.3741e-02,  9.8428e-02, -1.9289e-02, -2.2089e-02, -5.2654e-02,
         -4.1635e-02,  8.3131e-02,  3.4849e-02,  9.3343e-03,  4.0723e-02,
         -1.3263e-02,  2.8930e-02,  4.7990e-03, -7.8812e-03, -3.7410e-02,
         -1.9909e-02, -3.3280e-02, -9.4584e-02, -5.8618e-02, -2.7759e-02,
         -2.1408e-02, -1.0057e-01,  1.5220e-02, -9.7226e-03, -3.6858e-02,
          2.6987e-02,  2.2783e-02, -1.5646e-02,  4.5185e-02,  1.5173e-02,
         -3.0662e-02, -1.8342e-03, -9.5419e-03,  1.6222e-02,  3.3595e-02,
         -2.8728e-02,  4.7996e-02,  1.4539e-02,  2.3169e-02, -5.9801e-02,
         -5.6618e-02,  1.9532e-02, -4.8899e-02,  2.0007e-02,  9.6905e-02,
         -4.6016e-02,  7.7459e-02,  2.8737e-02, -2.9164e-02, -5.6729e-03,
         -4.6349e-03, -2.1344e-02, -1.2675e-02, -3.0075e-02, -4.6816e-02,
         -2.1749e-02,  4.0726e-02,  5.6176e-02, -9.7358e-03,  6.8359e-03,
          2.4994e-02, -5.1480e-02,  2.5092e-02,  4.9551e-02,  3.9513e-02,
         -3.7175e-02, -2.0377e-02,  1.1052e-02,  2.8294e-02,  1.8877e-03,
          3.1062e-02,  5.1838e-02, -3.7364e-02,  3.2560e-02,  1.2988e-02,
         -4.2784e-02,  5.3694e-02, -4.1841e-02, -4.2799e-02,  3.0533e-02,
          1.2768e-03,  4.1206e-02, -2.4335e-02,  5.2229e-02,  1.4089e-01,
          1.9144e-02, -6.9711e-02, -3.0000e-02, -1.9112e-02, -2.3986e-02,
          2.7377e-02,  9.9501e-03, -3.5863e-04,  9.6392e-03,  1.8683e-02,
          5.1291e-02, -8.0887e-02, -2.9901e-02, -1.1121e-01,  8.7469e-03,
          4.9067e-02,  7.3653e-02, -1.6569e-02, -3.5030e-02,  6.1487e-02,
         -1.3543e-02,  6.4453e-02,  9.6071e-03,  5.7289e-03,  1.9735e-02,
          3.9409e-02,  1.8790e-02}, 
          {-7.8181e-02, -7.0254e-02,  3.2573e-02, -2.7940e-02, -2.1239e-02,
         -6.6091e-02,  4.2237e-02, -2.3448e-02, -4.1770e-02,  3.3885e-02,
         -5.8204e-03, -2.5598e-02,  3.3447e-02,  9.8266e-02, -6.3344e-02,
         -1.0017e-02,  4.7564e-02,  1.3078e-02,  9.9959e-02, -1.4562e-02,
          8.0108e-04,  4.3802e-02,  3.1558e-04,  2.3659e-02,  5.3670e-03,
          6.1272e-02,  4.9823e-02,  7.0483e-03,  4.9498e-02,  5.5094e-02,
         -7.5500e-03, -5.6608e-02,  2.1019e-03, -1.5694e-02,  7.5347e-02,
         -4.5973e-02, -5.1214e-02, -2.8200e-02, -1.2135e-02, -7.2811e-02,
         -6.7294e-03,  7.5931e-02, -5.7148e-03,  2.1443e-02, -1.1141e-01,
          3.5499e-02, -1.6568e-02, -1.7620e-02,  4.7606e-02,  4.8820e-04,
          3.7483e-02,  1.0552e-02, -6.7351e-02,  1.8978e-02,  4.0032e-02,
          1.6453e-02,  1.2616e-02, -1.5525e-02,  6.9244e-02,  1.1096e-01,
          5.9247e-02,  1.4330e-02, -5.7698e-02, -6.3213e-02, -6.0728e-03,
         -2.8214e-02,  2.6712e-02,  9.0859e-02,  3.1562e-02, -2.1186e-02,
         -9.7141e-02,  1.6530e-02,  2.4526e-02,  6.2851e-02, -2.1852e-02,
          1.2019e-02, -1.5927e-02,  5.8785e-02, -5.6063e-02, -2.3128e-02,
         -5.7014e-02,  3.6719e-02,  7.1479e-02, -5.2705e-03, -3.8990e-02,
         -3.9625e-02,  2.6370e-02, -8.7944e-02, -4.2727e-02, -1.0499e-02,
          8.4495e-02, -9.2633e-03, -4.2764e-03,  4.4962e-02, -1.5587e-02,
          3.2153e-02, -7.3091e-02,  1.7887e-02, -7.3977e-02, -2.3726e-02,
         -4.1058e-03,  9.6020e-03, -1.1308e-02, -3.9431e-02,  3.4801e-02,
          2.8789e-03,  8.4675e-05, -2.4446e-03, -2.6016e-02, -2.9429e-02,
          4.4596e-02,  1.5505e-02, -3.3106e-02,  1.9270e-02,  4.5637e-02,
         -2.9469e-02,  5.3890e-03, -1.8244e-02, -1.0123e-03, -9.3617e-03,
          2.8347e-02, -6.3679e-02, -7.7533e-02,  9.8260e-03,  7.1389e-02,
          7.6669e-03, -3.7484e-02,  9.4790e-03, -2.9313e-02,  6.9544e-02,
         -1.0818e-02,  1.6433e-02,  3.0107e-02,  6.6112e-02, -1.0131e-01,
          2.6580e-02,  7.0041e-02,  1.7573e-02, -4.3651e-03, -2.7873e-02,
         -2.4054e-02,  2.0232e-02,  1.5075e-02,  3.1124e-02,  3.1721e-03,
         -4.4308e-02,  2.5408e-02, -5.1003e-02, -1.1428e-01, -1.1969e-02,
          3.3247e-02,  7.3484e-02, -3.2639e-02, -2.0778e-02, -5.3522e-03,
          3.7876e-02,  4.6758e-02, -5.9055e-03,  4.1445e-02, -6.5448e-02,
         -2.3133e-02, -1.2672e-01, -2.1008e-02, -5.5629e-02, -4.7930e-02,
          4.5228e-02, -6.2043e-02,  5.8784e-02, -2.7612e-02, -5.3454e-02,
         -4.4677e-02,  8.9916e-02, -9.4307e-02,  3.2748e-03,  1.3119e-02,
          5.7250e-03,  8.6726e-03,  5.9773e-02, -6.2486e-02, -5.2587e-02,
         -4.8227e-02, -9.3550e-03, -1.5769e-02, -7.3777e-02, -4.2227e-02,
         -3.4186e-02, -2.1633e-02, -2.0309e-02,  3.6595e-02, -6.4950e-02,
         -7.9779e-02, -2.5014e-02, -5.8263e-04, -5.8195e-03, -1.4713e-02,
          7.3894e-04, -3.5404e-03, -4.8105e-03,  7.6306e-02, -1.9263e-02,
         -6.3228e-02,  1.4541e-02, -5.2441e-03, -4.7894e-02,  5.3694e-02,
         -2.5775e-02, -8.2865e-02,  4.5811e-02, -4.0963e-02, -5.8693e-02,
          4.8322e-02,  4.0583e-04,  8.7179e-02, -1.5562e-02, -3.0811e-03,
         -1.1081e-01, -2.3143e-02, -3.5108e-02, -8.4195e-03,  1.5356e-02,
         -3.3173e-02, -2.9271e-02,  1.5747e-02, -7.3669e-02, -1.1971e-02,
         -6.3047e-02, -2.3830e-02, -4.5856e-03, -1.5974e-02,  2.7227e-02,
         -2.1875e-02, -4.5002e-02, -6.1277e-02,  8.3425e-02, -1.0243e-02,
         -4.2289e-02, -3.8146e-02,  1.8219e-02,  1.8134e-02, -3.0714e-02,
         -5.3793e-03, -6.9825e-02, -4.9923e-02,  5.0229e-02, -1.3575e-02,
          2.2626e-03, -8.2676e-03, -1.1715e-01,  2.5094e-02,  1.2766e-04,
         -1.6700e-02,  7.5030e-02,  1.0854e-02, -2.7370e-02,  5.9614e-03,
         -2.8906e-02,  4.4213e-03,  2.3265e-02, -8.2833e-03, -1.7880e-02,
         -3.3060e-02,  8.3250e-02,  1.5361e-02,  3.1760e-02, -1.9290e-02,
          5.7070e-02, -8.0477e-02, -1.4213e-03,  1.3551e-02,  5.9913e-02,
          5.2668e-03,  1.5887e-02,  5.2907e-02, -2.5783e-02,  3.4146e-02,
         -3.2782e-02, -7.2236e-02, -2.2427e-02,  3.8739e-02, -4.5754e-02,
          6.5422e-03, -1.1242e-02, -6.2779e-03, -1.4508e-02,  3.2028e-03,
         -5.9250e-03, -9.7912e-03,  4.5057e-02,  2.6775e-02,  4.8966e-02,
          1.7989e-02, -2.7573e-03,  4.8806e-02,  6.1214e-02,  6.6899e-02,
          1.1722e-02,  8.3664e-03,  3.8492e-02,  4.4502e-02,  3.3435e-02,
         -1.5339e-02,  7.3009e-03, -8.9756e-02,  2.6136e-02,  6.6216e-02,
         -9.6841e-02,  2.3327e-02,  2.2316e-04,  5.9164e-02, -2.1357e-02,
          4.0947e-02, -4.8726e-02, -5.3614e-02,  7.8556e-03,  2.3537e-02,
         -2.3257e-02, -2.7013e-02, -3.0213e-02, -2.6520e-02,  4.5928e-02,
         -1.5096e-02, -4.2754e-02,  1.1154e-02, -2.9922e-02,  5.6760e-02,
         -1.3639e-02,  1.9695e-02, -1.1512e-02, -2.9818e-02,  1.8744e-02,
         -8.2595e-03, -2.2096e-02,  4.2355e-02,  3.5187e-02,  2.1881e-02,
         -4.5930e-02,  2.6891e-02, -1.9128e-02,  1.3218e-02, -8.1844e-02,
         -2.1732e-02,  4.5487e-02,  8.1600e-03, -8.7721e-05,  4.5665e-02,
         -6.6576e-02, -9.1008e-02, -2.0252e-02,  2.1533e-03, -2.7359e-02,
          5.2538e-03,  6.5372e-02,  8.9547e-03, -4.9304e-02,  8.9362e-02,
         -1.2665e-02,  3.5337e-02, -5.1916e-02,  9.0831e-03,  5.8383e-03,
         -2.4958e-02, -3.3303e-02, -8.0794e-03,  1.2089e-02, -1.6288e-03,
          5.2204e-03, -1.9191e-02,  6.9335e-03, -4.2704e-02, -2.5944e-02,
         -7.5052e-02,  6.0547e-02, -1.0837e-01,  3.0809e-02, -1.1645e-03,
          3.5038e-02,  7.3659e-03,  2.1439e-02, -3.6391e-02,  4.3178e-02,
          1.2307e-02, -4.3183e-02,  2.2583e-02,  1.5433e-02,  2.6111e-02,
          9.0865e-03,  3.1028e-02,  5.1016e-04,  2.6014e-03,  1.7228e-02,
         -8.0901e-03,  6.5831e-02,  7.8651e-02, -1.1118e-01,  1.6258e-02,
          6.9780e-02, -2.1680e-02, -9.0581e-02, -2.0549e-02, -3.7485e-02,
          2.9378e-02, -1.8377e-02,  2.3672e-02,  8.6590e-02,  6.5898e-03,
          1.3294e-02,  6.5076e-03,  5.4714e-02,  6.9333e-02,  4.6319e-02,
          4.8681e-02,  2.7562e-02,  1.5177e-02, -5.1322e-03,  1.9259e-03,
          4.1518e-02,  4.3381e-04,  5.1120e-02,  2.0164e-02, -1.2498e-02,
          2.8420e-02, -4.5021e-02, -4.3918e-02, -1.5022e-02, -3.3367e-02,
          5.5660e-02, -3.5711e-02, -7.8152e-02,  3.0816e-02, -3.8968e-03,
          8.7023e-03, -3.2161e-02,  5.5787e-02,  3.9382e-02,  2.8148e-02,
         -5.0540e-02,  6.2678e-02,  1.0314e-02,  2.1063e-03, -1.3163e-02,
         -2.2842e-02, -2.7272e-02,  3.5333e-02, -6.0179e-03, -2.4316e-02,
         -1.9240e-02, -9.5908e-03,  8.3306e-02,  2.4683e-02, -1.2357e-02,
          9.8580e-03, -4.1790e-02, -1.0952e-01,  8.1180e-02,  4.7843e-02,
         -4.5159e-02, -4.5768e-03,  3.1659e-02,  6.9568e-02, -1.6418e-02,
         -7.8352e-02, -2.5351e-02,  9.7942e-03, -6.4216e-02,  1.7258e-03,
          7.5482e-02, -1.0392e-01, -1.7640e-02, -6.0129e-02,  6.5298e-03,
          1.3550e-01, -9.3190e-02, -1.2004e-02, -8.0961e-02,  2.8876e-03,
         -4.2618e-02,  8.8302e-03, -2.5474e-03,  1.9413e-02, -6.4721e-02,
          2.1967e-02,  2.8747e-02,  8.0546e-02,  5.2405e-02,  5.7515e-02,
         -4.9330e-02,  1.3510e-02, -4.3722e-02, -2.9042e-02, -2.7468e-03,
         -5.2179e-02, -4.5000e-02, -7.6638e-02, -1.0499e-02, -5.5902e-02,
          3.8399e-02,  1.0861e-01,  9.1209e-03, -3.4061e-02,  1.0144e-02,
         -5.4566e-03,  1.4174e-02,  2.2747e-02, -1.6427e-02, -8.9600e-03,
          1.6922e-02,  8.6429e-02,  3.5568e-02, -5.9468e-02, -1.5474e-02,
         -2.9565e-02, -2.8492e-02
    }};

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


    timeutils.start("Begin P");
    long C_range = 50;
    long m = 4;   
    long overlap = 0;
    long step_size = m - overlap;
    vector<long> C = generate_C(C_range, m);
    vector<long> E = generate_E(m);
    long remainder = n % step_size;
    long padding;
    if (remainder > 0) {
        padding = (step_size - remainder) % step_size;
    }
    else {
        padding = 0;
    }

    for(int i = 0; i < m; i++){
        cout << C[i] << " ";
    }
    cout << endl;

    for(int i = 0; i < m; i++){
        cout << E[i] << " ";
    }
    cout << endl;
    
    // int ref = 8;
    // vector<int> pairs{0, 0, 2, 2, 4, 4, 6, 6, 8, 8};
    for(int ref = 0; ref < embeddings.size(); ref++){
        for (int query = ref; query < embeddings.size(); query++) {
            // if ( query == ref || query == pairs[ref]){
            //     continue;
            // }
            cout << "Reference = " << ref << "    Query = " << query << endl;
            vector<double> reference_embeddings = embeddings[ref];
            vector<double> query_embeddings = embeddings[query];
            query_embeddings.resize(query_embeddings.size() + padding, 0.0);
            reference_embeddings.resize(reference_embeddings.size() + padding, 0.0);

            complex<double>* query_embeddings_new = new complex<double>[query_embeddings.size()];
            for (long i = 0; i < query_embeddings.size(); i++) {
                query_embeddings_new[i] = complex<double>(query_embeddings[i], 0.0);
            }
            complex<double>* reference_embeddings_new = new complex<double>[reference_embeddings.size()];
            for (long i = 0; i < reference_embeddings.size(); i++) {
                reference_embeddings_new[i] = complex<double>(reference_embeddings[i], 0.0);
            }

            cout << "Resizing done" << endl;
            vector<Ciphertext> query_embeddings_ciphers;
            for (long i = 0; i < query_embeddings.size() - m + 1; i+= step_size) {
                Ciphertext word_cipher;
                complex<double>* word_array = new complex<double>[m];
                for (long j = 0; j < m; j++){
                    word_array[j] = query_embeddings_new[i+j];
                }
                scheme.encrypt(word_cipher, word_array, m, logp, logq);
                query_embeddings_ciphers.push_back(word_cipher);
                word_cipher.free();
            }
            vector<Ciphertext> reference_embeddings_ciphers;
            for (long i = 0; i < reference_embeddings.size() - m + 1; i+= step_size) {
                Ciphertext word_cipher;
                complex<double>* word_array = new complex<double>[m];
                for (long j = 0; j < m; j++){
                    word_array[j] = reference_embeddings_new[i+j];
                }
                scheme.encrypt(word_cipher, word_array, m, logp, logq);
                reference_embeddings_ciphers.push_back(word_cipher);
                word_cipher.free();
            }

            cout << "Starting query P" << endl;
            vector<Ciphertext> query_P;
            int cnt_q = 0;
            for (auto i : query_embeddings_ciphers) {
                cnt_q ++;
                complex<double>* v0 = new complex<double>[m];
                for (long j = 0; j < m; j++) {
                    v0[j] = complex<double>(0.0,0.0);
                }
                Ciphertext temp_p;
                scheme.encrypt(temp_p, v0, m ,logp, logq);

                for (long j = 0; j < m; j++) {
                    complex<double>* temp = new complex<double>[m];
                    for (long k = 0; k < m; k++) {
                        temp[k] = complex<double>(0.0,0.0);
                    }
                    temp[j] = complex<double>(1.0, 0.0);
                    
                    Ciphertext temp_word, res;
                    scheme.encrypt(temp_word, temp, m, logp, logq);
                    scheme.multAndEqual(temp_word, i);
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
                    delete[] temp;
                    // break;
                }

                // cout << "Before sum" << endl;
                // complex<double>* temp_chk = scheme.decrypt(secretKey, temp_p);
                // for(int chk = 0; chk < m; chk++){
                //     cout << temp_chk[chk] << " ";
                // }
                // cout << endl;
                
                Ciphertext temp_sum_cipher;
                for (long j = m/2; j > 0; j/=2){
                    temp_sum_cipher.copy(temp_p);
                    temp_sum_cipher.logp = temp_p.logp;
                    temp_sum_cipher.logq = temp_p.logq;
                    scheme.leftRotateFastAndEqual(temp_sum_cipher, j);
                    scheme.addAndEqual(temp_p, temp_sum_cipher);
                }

                // cout << "After sum" << endl;
                // complex<double>* temp_chk2 = scheme.decrypt(secretKey, temp_p);
                // for(int chk = 0; chk < m; chk++){
                //     cout << temp_chk2[chk] << " ";
                // }
                // cout << endl;

            
                query_P.push_back(temp_p);
                //  if(cnt_q == 2){
                //     break;
                // }
                temp_sum_cipher.free();
                delete[] v0;        
            }
            cout << "Query P complete" << endl;

            cout << "Starting reference P" << endl;
            vector<Ciphertext> reference_P;
            int cnt_r = 0;
            for (auto i : reference_embeddings_ciphers) {
                cnt_r++;
                complex<double>* v0 = new complex<double>[m];
                for (long j = 0; j < m; j++) {
                    v0[j] = complex<double>(0.0,0.0);
                }
                Ciphertext temp_p;
                scheme.encrypt(temp_p, v0, m ,logp, logq);

                for (long j = 0; j < m; j++) {
                    complex<double>* temp = new complex<double>[m];
                    for (long k = 0; k < m; k++) {
                        temp[k] = complex<double>(0.0,0.0);
                    }
                    temp[j] = complex<double>(1.0, 0.0);
                    
                    Ciphertext temp_word, res;
                    scheme.encrypt(temp_word, temp, m, logp, logq);
                    scheme.multAndEqual(temp_word, i);
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
                    delete[] temp;
                    // break;
                }
                
                // cout << "Before sum" << endl;
                // complex<double>* temp_chk = scheme.decrypt(secretKey, temp_p);
                // for(int chk = 0; chk < m; chk++){
                //     cout << temp_chk[chk] << " ";
                // }
                // cout << endl;

                Ciphertext temp_sum_cipher;
                for (long j = m/2; j > 0; j/=2){
                    temp_sum_cipher.copy(temp_p);
                    temp_sum_cipher.logp = temp_p.logp;
                    temp_sum_cipher.logq = temp_p.logq;
                    scheme.leftRotateFastAndEqual(temp_sum_cipher, j);
                    scheme.addAndEqual(temp_p, temp_sum_cipher);
                }

                // cout << "After sum" << endl;
                // complex<double>* temp_chk2 = scheme.decrypt(secretKey, temp_p);
                // for(int chk = 0; chk < m; chk++){
                //     cout << temp_chk2[chk] << " ";
                // }
                // cout << endl;

            

                reference_P.push_back(temp_p);
                //  if(cnt_r == 2){
                //     break;
                // }
                temp_sum_cipher.free();
                delete[] v0;        
            }
            // cout << "Query P complete" << endl;

            // Calculating Squared Euclidian distance

            if (reference_P.size() != query_P.size()){
                cout << "Error, P sizes unequal" << endl;
            }

            // Assuming P size is a power of 2
            Ciphertext sed;

            for (long i = 0; i < reference_P.size(); i++) {
                scheme.multByConstAndEqual(query_P[i], -1.0, logp);
                scheme.reScaleByAndEqual(query_P[i], abs(query_P[i].logp - reference_P[i].logp));
                scheme.modDownToAndEqual(reference_P[i], query_P[i].logq);
                scheme.addAndEqual(reference_P[i], query_P[i]);
            }

            // complex<double>* temp_chk1 = scheme.decrypt(secretKey, reference_P[0]);
            // for(int chk = 0; chk < m; chk++){
            //     cout << temp_chk1[chk] << " ";
            // }
            // cout << endl;
            
            // complex<double>* temp_chk2 = scheme.decrypt(secretKey, reference_P[1]);
            // for(int chk = 0; chk < m; chk++){
            //     cout << temp_chk2[chk] << " ";
            // }
            // cout << endl;


            vector<Ciphertext> reference_P_sq;
            for (long i = 0; i < reference_P.size(); i++) {
                Ciphertext reference_sq;
                algo.powerOf2(reference_sq, reference_P[i], logp, 1);
                reference_P_sq.push_back(reference_sq);
                reference_sq.free();
            }

            
            // complex<double>* temp_chk3 = scheme.decrypt(secretKey, reference_P_sq[0]);
            // for(int chk = 0; chk < m; chk++){
            //     cout << temp_chk3[chk] << " ";
            // }
            // cout << endl;
            
            // complex<double>* temp_chk4 = scheme.decrypt(secretKey, reference_P_sq[1]);
            // for(int chk = 0; chk < m; chk++){
            //     cout << temp_chk4[chk] << " ";
            // }
            // cout << endl;

            sed.copy(reference_P_sq[0]);
            sed.logp = reference_P_sq[0].logp;
            sed.logq = reference_P_sq[0].logq;
            for (long i = 1; i < reference_P_sq.size(); i++) {
                scheme.addAndEqual(sed, reference_P_sq[i]);
            }

            complex<double>* true_val = new complex<double>[4];
            double true_val_temp = 0.0;
            for (int i = 0; i < n; i += m) {
                double true_query_P = 0.0;
                for (long k = i; k < i + m; k++) {
                    true_query_P += C[k%m]*pow(query_embeddings[k], E[k%m]);
                }

                double true_reference_P = 0.0;
                for (long k = i; k < i + m; k++) {
                    true_reference_P += C[k%m]*pow(reference_embeddings[k], E[k%m]);
                }

                true_val_temp += pow(true_reference_P - true_query_P, 2);
            }
            true_val[0] = complex<double>(true_val_temp, 0.0);
            true_val[1] = complex<double>(true_val_temp, 0.0);
            true_val[2] = complex<double>(true_val_temp, 0.0);
            true_val[3] = complex<double>(true_val_temp, 0.0);

            complex<double>* decrypt_p = scheme.decrypt(secretKey, sed);

            StringUtils::compare(true_val, decrypt_p, 2, "SED");
            
        }

    }
    
    timeutils.stop("End P");
    
}