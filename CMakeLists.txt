cmake_minimum_required(VERSION 3.5.1)
project(pcap_raw_socket)

set(CMAKE_CXX_STANDARD 14)

include_directories(libpcapcapture)
include_directories(helper)
add_executable(pcap_raw_socket main.cpp helper/PcapHelper.cpp
        libpcapcapture/packet.cpp helper/RawSocketHelper.cpp helper/JSONCPPHelper.cpp helper/TransNoNDN.cpp)

target_link_libraries(pcap_raw_socket pcap boost_system boost_thread jsoncpp)
