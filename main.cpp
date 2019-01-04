#include <iostream>
#include "EthernetTransport.hpp"
#include "TransNoNDN.h"
#include <boost/thread.hpp>
#include "helper/JSONCPPHelper.h"

using namespace IP_NDN_STACK::pcap;

void deal() {

}


int main(int argc, char **argv) {
    cout << argv[1] << endl;
    if (argc != 2) {
        cout << "usage: sudo ./pcap_raw_socket <config-file-path>" << endl;
        exit(-1);
    }
//
//    cout << "networkMonitor" << endl;
//    ndn::net::NetworkMonitor networkMonitor(service);
//    cout << "getInterface" << endl;
//    networkMonitor.onNetworkStateChanged.connect([&] {
//        cout << "network state change" << endl;
//    });
//
//    auto localInterface = networkMonitor.getNetworkInterface(argv[1]);
//    if (localInterface == nullptr) {
//        cout << "null" << endl;
//        return -1;
//    }

//    boost::thread t(deal);

    string configFile = argv[1];
    JSONCPPHelper jsoncppHelper(configFile);

    string interfaceName = jsoncppHelper.getString("pcap_if");
    string interfaceOutName = jsoncppHelper.getString("pcap_if_out");
    string localAddress = jsoncppHelper.getString("local_address");
    string remoteAddress = jsoncppHelper.getString("remote_address");

    TransNoNDN transNoNDN(interfaceName);
    transNoNDN.start();
//    boost::asio::io_service service;
//    IP_NDN_STACK::pcap::EthernetTransport transport(interfaceName, interfaceOutName, Address::fromString(localAddress),
//                                                    Address::fromString(remoteAddress), service);
//    service.run();


//    IP_NDN_STACK::pcap::PcapHelper pcapHelper(argv[1]);
//    RawSocketHelper rawSocketHelper;
//    pcapHelper.activate();
//
//    pcapHelper.setPacketFilter("ether proto \\ip");
//
//    struct timespec sleepTime {
//        0, 50
//    };
//    while (true) {
////        cout << endl << "begin: " << pcapHelper.getCurTime() << endl;
//        auto res = pcapHelper.readNextPacketAfterDecode();
//        auto tuple = (tuple_p) std::get<0>(res);
//        if (tuple == nullptr) {
////            cout << "tuple null" << endl;
//            continue;
//        }
//        uint32_t dip = ntohl(tuple->key.dst_ip);
//        string dstIP = to_string((dip >> 24) & 0xFF);
//        dstIP.append(".");
//        dstIP.append(to_string((dip >> 16) & 0xFF));
//        dstIP.append(".");
//        dstIP.append(to_string((dip >> 8) & 0xFF));
//        dstIP.append(".");
//        dstIP.append(to_string((dip >> 0) & 0xFF));
//        rawSocketHelper.sendPacketTo(tuple->pkt, tuple->size, dstIP);
////        cout <<  tuple->size << endl;
//        delete tuple;
////        cout << "end: " << pcapHelper.getCurTime() << endl;
//        nanosleep(&sleepTime, nullptr);
//    }

//    pcapHelper.close();
    return 0;
}