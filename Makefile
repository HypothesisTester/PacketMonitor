# Makefile
CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -pthread
LIBS = -lpcap -lncurses

SRC = src/main.cpp \
      src/PacketCapture.cpp \
      src/SignatureDetector.cpp \
      src/AnomalyDetector.cpp \
      src/Utils.cpp \
      src/UI.cpp

OBJ = $(SRC:.cpp=.o)
EXEC = bin/PacketMonitor

all: $(EXEC)

$(EXEC): $(OBJ)
	@mkdir -p bin
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f src/*.o $(EXEC)

.PHONY: all clean