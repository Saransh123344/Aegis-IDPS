cmake_minimum_required(VERSION 3.10)
project(AegisCoreDPI)

set(CMAKE_CXX_STANDARD 17)

add_executable(aegis_sniffer src/aegis_sniffer.cpp)

# Link the pcap library directly without find_package
target_link_libraries(aegis_sniffer pcap)