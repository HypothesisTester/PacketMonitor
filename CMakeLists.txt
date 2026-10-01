cmake_minimum_required(VERSION 3.16)
project(PacketMonitor VERSION 2.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

option(PM_BUILD_TESTS "Build the tests" ON)
option(PM_SANITIZE "Build with AddressSanitizer and UndefinedBehaviorSanitizer" OFF)

add_compile_options(-Wall -Wextra -Wpedantic)
if(PM_SANITIZE)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all)
  add_link_options(-fsanitize=address,undefined)
endif()

find_package(Threads REQUIRED)
find_path(PCAP_INCLUDE_DIR pcap/pcap.h)
find_library(PCAP_LIBRARY pcap)
if(NOT PCAP_INCLUDE_DIR OR NOT PCAP_LIBRARY)
  message(FATAL_ERROR "libpcap not found. On Debian or Ubuntu: sudo apt install libpcap-dev")
endif()

# The default signatures are compiled in, so the binary works from anywhere.
set(PM_SIGNATURES_FILE ${CMAKE_CURRENT_SOURCE_DIR}/data/signatures.txt)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${PM_SIGNATURES_FILE})
file(READ ${PM_SIGNATURES_FILE} PM_SIGNATURES)
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/DefaultSignatures.cpp.tmp
  "// Generated from data/signatures.txt. Do not edit.\n"
  "namespace pm {\n"
  "extern const char* const kDefaultSignatures;\n"
  "const char* const kDefaultSignatures = R\"PMSIG(${PM_SIGNATURES})PMSIG\";\n"
  "}\n")
configure_file(${CMAKE_CURRENT_BINARY_DIR}/DefaultSignatures.cpp.tmp
               ${CMAKE_CURRENT_BINARY_DIR}/DefaultSignatures.cpp COPYONLY)

if(APPLE)
  set(PM_OWNERS_PLATFORM src/procs/Owners_macos.cpp)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  set(PM_OWNERS_PLATFORM src/procs/Owners_linux.cpp)
else()
  set(PM_OWNERS_PLATFORM src/procs/Owners_other.cpp)
endif()

add_library(pmcore STATIC
  src/core/Packet.cpp
  src/core/Decoder.cpp
  src/core/Format.cpp
  src/analysis/AhoCorasick.cpp
  src/analysis/Signatures.cpp
  src/analysis/Dns.cpp
  src/analysis/Tls.cpp
  src/analysis/Services.cpp
  src/analysis/Detectors.cpp
  src/analysis/Engine.cpp
  src/procs/Owners.cpp
  ${PM_OWNERS_PLATFORM}
  src/capture/Capture.cpp
  src/ui/Terminal.cpp
  src/ui/Dashboard.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/DefaultSignatures.cpp)
target_include_directories(pmcore PUBLIC src ${PCAP_INCLUDE_DIR})
target_link_libraries(pmcore PUBLIC ${PCAP_LIBRARY} Threads::Threads)

add_executable(packetmonitor src/app/main.cpp)
target_link_libraries(packetmonitor PRIVATE pmcore)

# Writes the sample capture used by the tests, the demo and the benchmark.
add_executable(pm-sample tools/make_sample.cpp)
target_link_libraries(pm-sample PRIVATE pmcore)
add_custom_command(
  OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/sample.pcap ${CMAKE_CURRENT_BINARY_DIR}/sample.pcap.apps
  COMMAND pm-sample ${CMAKE_CURRENT_BINARY_DIR}/sample.pcap
  DEPENDS pm-sample
  COMMENT "Writing the sample capture")
add_custom_target(sample ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/sample.pcap)

# Compares Aho-Corasick with searching for each signature in turn.
add_executable(pm-bench-signatures tools/bench_signatures.cpp)
target_link_libraries(pm-bench-signatures PRIVATE pmcore)

include(GNUInstallDirs)
install(TARGETS packetmonitor RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

if(PM_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
