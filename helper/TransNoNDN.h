//
// Created by mingj on 19-1-4.
//

#ifndef PCAP_RAW_SOCKET_TRANSNONDN_H
#define PCAP_RAW_SOCKET_TRANSNONDN_H

#include "common.hpp"
#include "RawSocketHelper.h"
#include "PcapHelper.h"

using namespace IP_NDN_STACK::pcap;
class TransNoNDN {
public:
    class Error : public std::runtime_error {
    public:
        explicit
        Error(const std::string &what)
                : std::runtime_error(what) {
        }
    };

    TransNoNDN(const string &interfaceName);

    void
    asyncRead();

    void
    handleRead(const boost::system::error_code &error);

    void
    handleError(const std::string &errorMessage);

    void
    doClose();

    void
    start();
    ~TransNoNDN() = default;;

private:
    boost::asio::io_service service;
    boost::asio::posix::stream_descriptor m_socket;
    PcapHelper m_pcap;
    RawSocketHelper rawSocketHelper;
};


#endif //PCAP_RAW_SOCKET_TRANSNONDN_H
