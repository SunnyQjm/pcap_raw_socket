cmake_minimum_required(VERSION 3.11)
project(pcap_raw_socket)

set(CMAKE_CXX_STANDARD 14)

include_directories(libpcapcapture)
include_directories(helper)
add_executable(main.cpp helper/PcapHelper.cpp helper/RawSocketHelper.cpp libpcapcapture/packet.cpp)

target_link_libraries(pcap_raw_socket pcap)
