//
// Created by mingj on 19-1-4.
//

#include "TransNoNDN.h"

TransNoNDN::TransNoNDN(const string &interfaceName)
        : m_socket(service)
        , m_pcap(interfaceName){
    try {
        cout << "pcap active" << endl;
        m_pcap.activate();
        m_pcap.setPacketFilter("ether proto \\ip");

        m_socket.assign(m_pcap.getFd());
    } catch (const PcapHelper::Error &e) {
        BOOST_THROW_EXCEPTION(Error(e.what()));
    }

    asyncRead();
}

void TransNoNDN::asyncRead() {
    m_socket.async_read_some(boost::asio::null_buffers(),
                             [this](const auto &e, auto) { this->handleRead(e); });
}

struct timespec sleepTime{
        0, 100
};

void TransNoNDN::handleRead(const boost::system::error_code &error) {
    if (error) {
        cout << "error: " << error;
        return;
    }
    // 只用async read, 还是用Raw Socket 发包，速率没有提升
    auto res = m_pcap.readNextPacketAfterDecode();
    auto tuple = (tuple_p) std::get<0>(res);
    if (tuple != nullptr) {
        uint32_t dip = ntohl(tuple->key.dst_ip);
        string dstIP = to_string((dip >> 24) & 0xFF);
        dstIP.append(".");
        dstIP.append(to_string((dip >> 16) & 0xFF));
        dstIP.append(".");
        dstIP.append(to_string((dip >> 8) & 0xFF));
        dstIP.append(".");
        dstIP.append(to_string((dip >> 0) & 0xFF));
        rawSocketHelper.sendPacketTo(tuple->pkt, tuple->size, dstIP);
        nanosleep(&sleepTime, nullptr);
    }
    delete tuple;
    asyncRead();

    return;
}

void TransNoNDN::handleError(const std::string &errorMessage) {
    cerr << "ERROR: " << errorMessage << endl;
    doClose();
}

void TransNoNDN::doClose() {
    if (m_socket.is_open()) {
        // Cancel all outstanding operations and close the socket.
        // Use the non-throwing variants and ignore errors, if any.
        boost::system::error_code error;
        m_socket.cancel(error);
        m_socket.close(error);
    }
    m_pcap.close();
}

void TransNoNDN::start() {
    cout << "run" << endl;
    service.run();
}
