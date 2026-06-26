TARGET = pcap-test
CXX = g++
CXXFLAGS = -Wall -O2 -std=c++11

all: $(TARGET)

$(TARGET): main.o
	$(CXX) $(CXXFLAGS) -o $(TARGET) main.o -lpcap

main.o: main.cpp
	$(CXX) $(CXXFLAGS) -c main.cpp

clean:
	rm -f $(TARGET) *.o
