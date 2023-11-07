

CVPATH=/usr/include/opencv4/
CVLINKERS=-L/usr/lib -lopencv_core -lopencv_imgcodecs -lopencv_highgui -lopencv_imgproc
HEAANLINKERS=../lib/libHEAAN.a -lntl -lgmp -lm -std=c++11 -O2 -I/../src -pthread

all: clean main_ada

main:
	g++ main.cpp -I $(CVPATH) $(CVLINKERS) -L/usr/local/lib ../lib/libHEAAN.a -lntl -lgmp -lm -std=c++11  -I/../src -pthread

main_ada:
	g++ main_adaface.cpp -I $(CVPATH) $(CVLINKERS) -L/usr/local/lib ../lib/libHEAAN.a -lntl -lgmp -lm -std=c++11  -I/../src -pthread

main_d:
	g++ main_dissimilar.cpp -I $(CVPATH) $(CVLINKERS) -L/usr/local/lib ../lib/libHEAAN.a -lntl -lgmp -lm -std=c++11  -I/../src -pthread		

computeTrue:
	g++ computeTrue.cpp -I $(CVPATH) $(CVLINKERS) -L/usr/local/lib ../lib/libHEAAN.a -lntl -lgmp -lm -std=c++11  -I/../src -pthread	

dotProduct:
	g++ dotProduct.cpp -I $(CVPATH) $(CVLINKERS) -L/usr/local/lib ../lib/libHEAAN.a -lntl -lgmp -lm -std=c++11  -I/../src -pthread	

heftDotProduct:
	g++ heftDotProduct.cpp -I $(CVPATH) $(CVLINKERS) -L/usr/local/lib ../lib/libHEAAN.a -lntl -lgmp -lm -std=c++11  -I/../src -pthread	

sed:
	g++ sed.cpp -I $(CVPATH) $(CVLINKERS) -L/usr/local/lib ../lib/libHEAAN.a -lntl -lgmp -lm -std=c++11  -I/../src -pthread	

invSqRoot:
	g++ inv_sq_root.cpp -I $(CVPATH) $(CVLINKERS) -L/usr/local/lib ../lib/libHEAAN.a -lntl -lgmp -lm -std=c++11  -I/../src -pthread	

zeroFinding:
	g++ zero_finding.cpp -I $(CVPATH) $(CVLINKERS) -L/usr/local/lib ../lib/libHEAAN.a -lntl -lgmp -lm -std=c++11  -I/../src -pthread	

demoheaan:
	g++ crypt_fft.cpp -I $(CVPATH) $(CVLINKERS) $(HEAANLINKERS)
	@echo 'DONE'

demofftconvo:
	g++ fft_convo.cpp -I $(CVPATH) $(CVLINKERS) $(HEAANLINKERS)

# Tool invocations
democv:
	@echo 'Building target: $@'
	@echo 'Invoking: GCC C++ Linker'
	g++ fft_convo.cpp -L/usr/local/lib ../lib/libHEAAN.a -lntl -lgmp -lm -std=c++11 -O2 -I/../src -pthread
	@echo 'Finished building target: $@'
	@echo ' '




# Other Targets
clean:
	rm -rf demo
