//
// Created by mingj on 19-1-3.
//

#ifndef PCAP_RAW_SOCKET_ETHERNETPROTOCOL_H
#define PCAP_RAW_SOCKET_ETHERNETPROTOCOL_H

#include <net/ethernet.h>
#include <ndn-cxx/net/ethernet.hpp>

using namespace ndn::ethernet;

namespace IP_NDN_STACK {
    namespace pcap {
        std::pair<const ether_header*, std::string>
        checkFrameHeader(const uint8_t* packet, size_t length,
                         const Address& localAddr, const Address& destAddr);
    }
}

#endif //PCAP_RAW_SOCKET_ETHERNETPROTOCOL_H
