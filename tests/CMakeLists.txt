find_package(GTest QUIET)
if(NOT GTest_FOUND)
  include(FetchContent)
  FetchContent_Declare(googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.15.2.tar.gz
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
  set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
  FetchContent_MakeAvailable(googletest)
endif()
include(GoogleTest)

add_executable(pm-tests
  test_decoder.cpp
  test_ring.cpp
  test_aho_corasick.cpp
  test_signatures.cpp
  test_dns.cpp
  test_tls.cpp
  test_detectors.cpp
  test_owners.cpp
  test_format.cpp
  test_terminal.cpp
  test_robustness.cpp
  test_engine.cpp)
target_link_libraries(pm-tests PRIVATE pmcore GTest::gtest_main)
target_compile_definitions(pm-tests PRIVATE PM_SAMPLE_PCAP="${CMAKE_BINARY_DIR}/sample.pcap")
add_dependencies(pm-tests sample)
gtest_discover_tests(pm-tests DISCOVERY_TIMEOUT 60)

# The command line, end to end on the sample capture.
add_test(NAME cli_headless_sample
  COMMAND packetmonitor --read ${CMAKE_BINARY_DIR}/sample.pcap --headless)
set_tests_properties(cli_headless_sample PROPERTIES
  PASS_REGULAR_EXPRESSION "Port scan.*SYN flood|SYN flood.*Port scan")
add_test(NAME cli_bench_sample
  COMMAND packetmonitor --read ${CMAKE_BINARY_DIR}/sample.pcap --bench)
set_tests_properties(cli_bench_sample PROPERTIES PASS_REGULAR_EXPRESSION "million packets/s")
add_test(NAME cli_rejects_bad_signatures
  COMMAND packetmonitor --read ${CMAKE_BINARY_DIR}/sample.pcap --headless -s ${CMAKE_CURRENT_SOURCE_DIR}/bad_signatures.txt)
set_tests_properties(cli_rejects_bad_signatures PROPERTIES WILL_FAIL TRUE)
