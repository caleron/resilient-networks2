cmake_minimum_required(VERSION 3.6)
project(resilient_networks2)

set(CMAKE_CXX_STANDARD 11)
link_libraries(pcap)

set(SOURCE_FILES pcap_task.cc)
add_executable(resilient_networks2 ${SOURCE_FILES})