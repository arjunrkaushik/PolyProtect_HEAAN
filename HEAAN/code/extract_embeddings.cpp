#include <dlib/dnn.h>
#include <dlib/opencv.h>
#include <opencv2/opencv.hpp>
#include <vector>

using namespace dlib;

int main() {
    try {
        // Load the pre-trained face recognition model
        shape_predictor sp;
        deserialize("shape_predictor_68_face_landmarks.dat") >> sp;

        // Load an image using OpenCV
        cv::Mat inputImage = cv::imread("input.jpg");

        // Convert the OpenCV image to Dlib's image format
        dlib::cv_image<dlib::bgr_pixel> dlibImage(inputImage);

        // Detect faces and facial landmarks in the image
        std::vector<dlib::full_object_detection> landmarks = sp(dlibImage);

        // Extract face embeddings
        std::vector<std::vector<int>> faceEmbeddings;

        // Loop through detected faces and compute embeddings
        for (const auto& landmark : landmarks) {
            matrix<float, 0, 1> faceDescriptor = dlib::matrix_cast<float>(dlib::mean(dlib::rowm(mat(landmark), dlib::range(17, 67))));

            // Convert face embeddings to integers using OpenCV
            std::vector<int> intFaceEmbedding;
            for (int i = 0; i < faceDescriptor.size(); ++i) {
                intFaceEmbedding.push_back(static_cast<int>(std::round(faceDescriptor(i) * 1000))); // You can adjust the scaling factor as needed
            }

            faceEmbeddings.push_back(intFaceEmbedding);
        }

        // You now have the face embeddings as vectors of integers in 'faceEmbeddings'

    } catch (std::exception& e) {
        std::cout << "Error: " << e.what() << std::endl;
    }

    return 0;
}
