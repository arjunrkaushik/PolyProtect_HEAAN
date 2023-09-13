

CVPATH=/usr/include/opencv4/
CVLINKERS=-L/usr/lib -lopencv_core -lopencv_imgcodecs -lopencv_highgui -lopencv_imgproc
HEAANLINKERS=../lib/libHEAAN.a -lntl -lgmp -lm -std=c++11 -O2 -I/../src -pthread

all: clean main

main:
	g++ main.cpp -I $(CVPATH) $(CVLINKERS) -L/usr/local/lib ../lib/libHEAAN.a -lntl -lgmp -lm -std=c++11  -I/../src -pthread		

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
