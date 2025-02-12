# PacketMonitor

**Real-Time Packet Monitoring Tool**

## Overview

PacketMonitor is a C++ application that captures network packets in real time using libpcap, performs signature-based deep packet inspection (DPI) to identify malicious payloads, and detects traffic anomalies using a sliding time window algorithm. A dynamic command-line interface (CLI) built with ncurses displays flagged packets and anomalies, while an advanced logging system records events with automatic log rotation.

## Folder Structure

PacketMonitor/
├── bin/
│   └── (Compiled executable)
├── data/
│   └── signatures.txt  (List of malicious patterns)
├── src/
│   ├── AnomalyDetector.h       (Anomaly detection module header)
│   ├── AnomalyDetector.cpp     (Anomaly detection implementation)
│   ├── PacketCapture.h         (Packet capture module header)
│   ├── PacketCapture.cpp       (Packet capture implementation)
│   ├── SignatureDetector.h     (Signature detection module header)
│   ├── SignatureDetector.cpp   (Signature detection implementation)
│   ├── UI.h                  (User interface module header)
│   ├── UI.cpp                (User interface implementation)
│   ├── Utils.h               (Utility functions header)
│   ├── Utils.cpp             (Utility functions implementation)
│   └── main.cpp              (Application entry point)
├── tests/                (Optional: Unit tests)
│   ├── CMakeLists.txt    (CMake config for tests)
│   ├── test_AnomalyDetector.cpp
│   ├── test_SignatureDetector.cpp
│   └── test_Utils.cpp
├── Makefile              (Build instructions)
└── README.md             (Project documentation)

## Tools Used

- **Programming Language:** C++
- **Libraries:** libpcap (packet capturing), ncurses (CLI), Google Test (unit testing)
- **Build Tools:** Make, CMake (for tests)
- **Deployment:** systemd (optional for service integration)

## Getting Started

### Prerequisites

Ensure you have the following installed on your system:
- **g++** (C++ compiler)
- **libpcap-dev** (development files for libpcap)
- **libncurses5-dev** (development files for ncurses)
- **make** (build automation tool)

### Building the Project

1. **Open a Terminal in the PacketMonitor Folder**  
   Navigate to your project’s root folder:

   cd /path/to/PacketMonitor

2. **Build Using the Makefile**  
    Run:

    make

    This command compiles the source code and places the executable in the bin/ directory.

### Running the Application

You will likely need root privileges to capture network packets. Run:

sudo ./bin/PacketMonitor


### Command-Line Options

You can customize the execution by using command-line options:
- **-i, --interface** — Network interface to capture packets (default: eth0)
- **-f, --filter** — BPF filter expression (default: "tcp or udp")
- **-s, --signatures** — Path to signatures file (default: data/signatures.txt)
- **-t, --threshold** — Anomaly detection threshold (default: 1000)
- **-w, --window** — Time window in seconds for anomaly detection (default: 60)
- **-h, --help** — Display this help message

### Using the Application

- **Dynamic CLI:**  
  The ncurses-based interface displays flagged packets and anomalies in real time.

- **Exiting:**  
  Press `q` or `Q` at any time to quit the application.

### Running Unit Tests

The project includes unit tests for the anomaly detection, signature detection, and utility functions using Google Test.

1. **Install Google Test**  
   On Ubuntu, install Google Test and CMake:

  sudo apt-get update
  sudo apt-get install libgtest-dev cmake


Then build Google Test:

  cd /usr/src/gtest
  sudo cmake CMakeLists.txt
  sudo make
  sudo cp lib/*.a /usr/lib

### Building the Tests

1. **Open a Terminal in the tests Folder**  
Navigate to your tests folder inside your PacketMonitor project:

  cd /path/to/PacketMonitor/tests 

2. **Create a Build Directory and Run CMake:**

  mkdir build && cd build
  cmake ..
  make

This will compile the test executables: test_AnomalyDetector, test_SignatureDetector, and test_Utils.

### Running the Tests

Run each test executable individually:

  ./test_AnomalyDetector
  ./test_SignatureDetector
  ./test_Utils

Alternatively, if you have configured CTest, run:

  ctest