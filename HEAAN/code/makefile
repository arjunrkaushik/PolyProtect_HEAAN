

CVPATH=/usr/include/opencv4/
CVLINKERS=-L/usr/lib -lopencv_core -lopencv_imgcodecs -lopencv_highgui -lopencv_imgproc
HEAANLINKERS=../lib/libHEAAN.a -lntl -lgmp -lm -std=c++11 -O2 -I/../src -pthread

all: clean build_pp main_m8

build_pp: 
	g++ -c PolyProtectTemplate.cpp -o polyprotect.o -I $(CVPATH) $(CVLINKERS) -L/usr/local/lib ../lib/libHEAAN.a -lntl -lgmp -lm -std=c++11  -I/../src -pthread

main:
	g++ main.cpp -I $(CVPATH) $(CVLINKERS) -L/usr/local/lib ../lib/libHEAAN.a -lntl -lgmp -lm -std=c++11  -I/../src -pthread

main_m8: 
	g++ polyprotect.o main_m8.cpp -I $(CVPATH) $(CVLINKERS) -L/usr/local/lib ../lib/libHEAAN.a -lntl -lgmp -lm -std=c++11  -I/../src -pthread

main_ada_sed:
	g++ main_adaface_sed.cpp -I $(CVPATH) $(CVLINKERS) -L/usr/local/lib ../lib/libHEAAN.a -lntl -lgmp -lm -std=c++11  -I/../src -pthread

main_ada_cosine:
	g++ main_adaface_cosine.cpp -I $(CVPATH) $(CVLINKERS) -L/usr/local/lib ../lib/libHEAAN.a -lntl -lgmp -lm -std=c++11  -I/../src -pthread

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

cosine:
	g++ cosine.cpp -I $(CVPATH) $(CVLINKERS) -L/usr/local/lib ../lib/libHEAAN.a -lntl -lgmp -lm -std=c++11  -I/../src -pthread	

newtonsInvSqRoot:
	g++ newtons_inv_sq_root.cpp -I $(CVPATH) $(CVLINKERS) -L/usr/local/lib ../lib/libHEAAN.a -lntl -lgmp -lm -std=c++11  -I/../src -pthread	

zeroFinding:
	g++ zero_finding.cpp -I $(CVPATH) $(CVLINKERS) -L/usr/local/lib ../lib/libHEAAN.a -lntl -lgmp -lm -std=c++11  -I/../src -pthread

invSqRootPoly:
	g++ inv_sq_root_poly.cpp -I $(CVPATH) $(CVLINKERS) -L/usr/local/lib ../lib/libHEAAN.a -lntl -lgmp -lm -std=c++11  -I/../src -pthread	

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
