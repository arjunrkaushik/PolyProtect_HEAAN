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

namespace std {
    vector<long> generate_C(long C_range, long m);
    vector<long> generate_E(long m);
    vector<double> polyprotect(long overlap, vector<double> V, vector<double> C, vector<long> E);
}