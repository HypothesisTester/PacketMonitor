# PacketMonitor

PacketMonitor is a C++ CLI tool that captures live network traffic, inspects packets for known signatures, and spots anomalies in real time using libpcap and ncurses.

## Features
- Real-time capture with per-interface filtering via libpcap
- Signature-based DPI backed by `data/signatures.txt`
- Sliding-window anomaly detection with configurable thresholds
- ncurses dashboard plus rotating event logs for flagged activity

## Requirements
Install the following build-time dependencies:
- g++ and make
- libpcap with headers
- ncurses with headers
- (Tests) CMake and Google Test

macOS (Apple Silicon) users can install missing tools with Homebrew, e.g. `brew install libpcap ncurses cmake googletest` (packages live under `/opt/homebrew`).

## Build & Run
```sh
# from the project root
make
sudo ./bin/PacketMonitor [options]
```
`sudo` is required for raw packet capture. The executable is written to `bin/`.

## Configuration
Key runtime flags:
- `-i, --interface` network interface (default `eth0`)
- `-f, --filter` BPF filter (default `"tcp or udp"`)
- `-s, --signatures` signature file path (default `data/signatures.txt`)
- `-t, --threshold` anomaly score threshold (default `1000`)
- `-w, --window` sliding window size in seconds (default `60`)
- `-h, --help` show full usage

Press `q` at any time to exit the ncurses dashboard.

## Tests
```sh
cd tests
rm -rf build
cmake -B build -S . -DGTEST_ROOT=/opt/homebrew/opt/googletest
cmake --build build
ctest --test-dir build
```
Adjust `-DGTEST_ROOT` if Google Test is installed elsewhere.

## Project Layout
- `src/` core modules (`PacketCapture`, `SignatureDetector`, `AnomalyDetector`, `UI`, `Utils`)
- `data/` default signature set
- `bin/` compiled binaries
- `tests/` Google Test suites
- `log.txt` rotating log output
- `Makefile` build entry point
