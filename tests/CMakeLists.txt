cmake_minimum_required(VERSION 3.10)
project(PacketMonitorTests)

set(CMAKE_CXX_STANDARD 17)

# Enable testing so that CTest can find tests.
enable_testing()

# Find GoogleTest (installed via Homebrew on M1, usually under /opt/homebrew)
find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS} ../src)

# Collect all source files from the src folder
file(GLOB SRC_FILES "../src/*.cpp")
# Remove main.cpp from the list so that our test library doesn't contain an extra main()
list(REMOVE_ITEM SRC_FILES "${CMAKE_CURRENT_SOURCE_DIR}/../src/main.cpp")

# Build a static library from all the source files in the src folder (excluding main.cpp)
add_library(PacketMonitorLib STATIC ${SRC_FILES})
target_include_directories(PacketMonitorLib PUBLIC ../src)

# Build test for AnomalyDetector
add_executable(test_AnomalyDetector test_AnomalyDetector.cpp)
target_link_libraries(test_AnomalyDetector PacketMonitorLib GTest::GTest GTest::Main pthread)
add_test(NAME AnomalyDetectorTest COMMAND test_AnomalyDetector)

# Build test for SignatureDetector
add_executable(test_SignatureDetector test_SignatureDetector.cpp)
target_link_libraries(test_SignatureDetector PacketMonitorLib GTest::GTest GTest::Main pthread)
add_test(NAME SignatureDetectorTest COMMAND test_SignatureDetector)

# Build test for Utils
add_executable(test_Utils test_Utils.cpp)
target_link_libraries(test_Utils PacketMonitorLib GTest::GTest GTest::Main pthread)
add_test(NAME UtilsTest COMMAND test_Utils)