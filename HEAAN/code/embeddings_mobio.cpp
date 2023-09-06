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

tuple<vector<double>, vector<double>, vector<double>, vector<vector<double>>> calc_embedding_distributions(vector<vector<double>> embeddings, int precision) {
    """ Calculates the probability distribution of each embedding element (i.e., dimension) separately. 

    **Inputs:**

    embeddings : 2D numpy array
        A 2D numpy array of all embeddings that you wish to use to plot the distribution, where each row corresponds to a different embedding. 

    precision : int
        Specifies the number of digits after the decimal point to which the embedding values should be rounded. 

    **Outputs:**

    means : 1D numpy array (1 value per embedding element)
        The mean of each embedding element's distribution.

    mins : 1D numpy array (1 value per embedding element)
        The minimum of each embedding element's distribution.

    maxs : 1D numpy array (1 value per embedding element)
        The maximum of each embedding element's distribution.

    """
    int num_elements = embeddings[0].size();

    vector<double> means(num_elements, 0.0);
    vector<double> mins(num_elements, 0.0);
    vector<double> maxs(num_elements, 0.0); 
    vector<vector<double>> probabilities;

    double step_size = 1.0 * pow(10, -precision);

    for (int el_idx = 0; el_idx < num_elements; el_idx++) {
        vector<double> elements;
        for (int i = 0; i < embeddings.size(); i++) {
            elements.push_back(embeddings[i][el_idx]);
        }
        vector<double> elements_rounded;
        for (int i = 0; i < elements.size(); i++) {
            elements_rounded.push_back(round(elements[i] * pow(10, precision)) / pow(10, precision));
        }

        mins[el_idx] = elements_rounded[0];
        maxs[el_idx] = elements_rounded[0];
        for (auto i:elements_rounded) {
            means[el_idx] += i;
            mins[el_idx] = min(mins[el_idx], i);
            maxs[el_idx] = max(mins[el_idx], i);
        }
        means[el_idx] /= elements_rounded.size();

        std::vector<double> counts;
        std::vector<double> bin_edges;
        for (double bin = mins[el_idx]; bin <= maxs[el_idx] + 2 * step_size; bin += step_size) {
            bin_edges.push_back(bin);
            double count = 0;
            for (int i = 0; i < elements_rounded.size(); i++) {
                if (elements_rounded[i] >= bin && elements_rounded[i] < bin + step_size) {
                    count++;
                }
            }
            counts.push_back(count);
        }
        
        std::vector<double> probs(counts.size());
        for (int i = 0; i < counts.size(); i++) {
            probs[i] = counts[i] / elements_rounded.size();
        }
        probabilities.push_back(probs);
    }

    return make_tuple(means, mins, maxs, probabilities);
}