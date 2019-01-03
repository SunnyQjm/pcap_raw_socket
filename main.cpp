#include <iostream>
#include "helper/PcapHelper.h"
#include "helper/RawSocketHelper.h"
#include "packet.h"

int main(int argc, char **argv) {
    cout << argv[1] << endl;
    if (argc != 2) {
        cout << "usage: sudo ./pcap_raw_socket <interface name>" << endl;
        exit(-1);
    }
    PcapHelper pcapHelper(argv[1]);
    RawSocketHelper rawSocketHelper;
    pcapHelper.activate();

    pcapHelper.setPacketFilter("ether proto \\ip");

    while (true) {
        cout << endl << "begin: " << pcapHelper.getCurTime() << endl;
        auto res = pcapHelper.readNextPacket();
        auto tuple = (tuple_p) std::get<0>(res);
        if (tuple == nullptr) {
//            cout << "tuple null" << endl;
            continue;
        }
        uint32_t dip = ntohl(tuple->key.dst_ip);
        string dstIP = to_string((dip >> 24) & 0xFF);
        dstIP.append(".");
        dstIP.append(to_string((dip >> 16) & 0xFF));
        dstIP.append(".");
        dstIP.append(to_string((dip >> 8) & 0xFF));
        dstIP.append(".");
        dstIP.append(to_string((dip >> 0) & 0xFF));
        rawSocketHelper.sendPacketTo(tuple->pkt, tuple->size, dstIP);
        delete tuple;
        cout << "end: " << pcapHelper.getCurTime() << endl;
    }

    pcapHelper.close();
    return 0;
}