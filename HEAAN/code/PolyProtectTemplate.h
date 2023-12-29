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

using namespace std;
using namespace heaan;
using namespace NTL;

class PolyProtectTemplate {
    public:
        vector<long> generateC(long C_range, long m);
        vector<long> generateE(long m);
        vector<Ciphertext> generateTemplate(vector<Ciphertext> embeddings_ciphers, long cipher_m, long m, SecretKey &secretKey, Scheme &scheme, SchemeAlgo &algo, long logp, long logq);    
};