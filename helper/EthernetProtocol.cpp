//
// Created by mingj on 19-1-3.
//

#include "EthernetProtocol.hpp"
#include <cstring>
#include <boost/endian/conversion.hpp>

namespace IP_NDN_STACK {
    namespace pcap {
        std::pair<const ether_header *, std::string>
        checkFrameHeader(const uint8_t *packet, size_t length,
                         const Address &localAddr, const Address &destAddr) {
            if (length < HDR_LEN + MIN_DATA_LEN) {

                return {nullptr, "Received frame too short: " + std::to_string(length) + " bytes"};
            }

            const auto *eh = reinterpret_cast<const ether_header *>(packet);

            // in some cases VLAN-tagged frames may survive the BPF filter,
            // make sure we do not process those frames (see #3348)
            uint16_t ethertype = boost::endian::big_to_native(eh->ether_type);
//            if (ethertype != ETHERTYPE_NDN)
//                return {nullptr, "Received frame with wrong ethertype: " + std::to_string(ethertype)};

#ifdef _DEBUG
            Address shost(eh->ether_shost);
          if (shost == localAddr)
            return {nullptr, "Received frame sent by this host"};

          Address dhost(eh->ether_dhost);
          if (dhost != destAddr)
            return {nullptr, "Received frame addressed to another host or multicast group: " + dhost.toString()};
#endif

            return {eh, ""};
        }
    }
}