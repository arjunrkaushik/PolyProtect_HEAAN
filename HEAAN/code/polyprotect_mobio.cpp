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


using namespace cv;
using namespace heaan;
using namespace std;
using namespace NTL;

vector<int> generate_C(int C_range, int m) {
    """ Randomly generates m coefficients for the PolyProtect mapping.

    **Inputs:**

    C_range : integer
        The absolute min/max values of the coefficients range. 

    m : int
        The number of coefficients to generate.

    **Outputs:**

    C : 1D numpy array of integers
        Array of m coefficients.

    """
    vector<int> neg_range, pos_range, whole_range;

    for (int i = -1*C_range; i < 0; i++) {
        neg_range.push_back(i);
    }
    for (int i = 1; i < C_range + 1; i++) {
        neg_range.push_back(i);
    }
    for (auto i:neg_range) {
        whole_range.push_back(i);
    }
    for (auto i:pos_range) {
        whole_range.push_back(i);
    }

    shuffle(whole_range.begin(), whole_range.end(), random_device());
    
    vector<int> C(whole_range.begin(), whole_range.begin() + m);

    return C;

}

vector<int> generate_E(int m) {
    """ Randomly generates m exponents for the PolyProtect mapping.

    **Inputs:**

    m : int
        The number of exponents to generate.

    **Outputs:**

    E : 1D numpy array of integers
        Array of m exponents.

    """

    vector<int> E;

    for (int i = 1; i < m + 1; i++) {
        E.push_back(i);
    }

    shuffle(E.begin(), E.end(), random_device());

    return E;    

}

vector<float> polyprotect(int overlap, vector<float> V, vector<int> C, vector<int> E) {
     """ Maps an embedding to a PolyProtected template.

    **Inputs:**

    overlap : int
        The amount of overlap between sets of embedding elements used to generate each PolyProtected element (0, 1, 2, 3, or 4).

    V : 1D numpy array of floats
        The embedding.

    C : 1D numpy array of integers
        The coefficients used for the PolyProtect mapping. 

    E : 1D numpy array of integers
        The exponents used for the PolyProtect mapping. 

    **Outputs:**

    P : 1D numpy array of floats
        The PolyProtected template.

    """

    if (C.size() != E.size()) {
        cout << "Number of coefficients and exponents must be the same." << endl;
    }

    """Generate the PolyProtected template, P:"""
    int m = C.size();  """number of embedding elements used to generate each PolyProtected element"""
    int step_size = m - overlap;

    double decimal_remainder, integer;
    integer = modf((V.size() - m) / step_size, &decimal_remainder);

    int padding;
    if(decimal_remainder > 0){
        padding = ceil((1 - decimal_remainder) * step_size);
    }
    else {
        padding = 0;
    }

    V.resize(V.size() + padding, 0);

    vector<int> starting_indices;
    for (int i = 0; i < V.size() - m + 1; i += step_size) {
        starting_indices.push_back(i);
    }

    vector<double> P(starting_indices.size(), 0.0);

    int storage_ind = 0;
    for (auto ind:starting_indices) {
        int final_ind = ind + m;
        vector<int> crnt_word(V.begin() + ind, V.begin() + final_ind);
        for (int i = 0; i < m; i++) {
            P[storage_ind] += C[i] * pow(crnt_word[i], E[i]);
        }
        storage_ind++;
    }
    
    return P;

}

