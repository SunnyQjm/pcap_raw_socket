//
// Created by mingj on 19-1-3.
//

#include "EthernetTransport.hpp"

#include <boost/asio/buffer.hpp>
#include <vector>

namespace IP_NDN_STACK {
    namespace pcap {


        EthernetTransport::Packet::Packet(Block &&packet1)
                : packet(std::move(packet1)), remoteEndpoint(0) {}

        EthernetTransport::EthernetTransport(const string &interfaceName, const string &outInterfaceName,
                                             const ethernet::Address &localAddress,
                                             const ethernet::Address &remoteEndpoint, boost::asio::io_service &service)
                : m_socket(service), m_socket_out(service), m_pcap(interfaceName), m_pcap_out(outInterfaceName),
                  m_srcAddress(localAddress), m_destAddress(remoteEndpoint),
                  m_interfaceName(interfaceName), m_hasRecentlyReceived(false)
#ifdef _DEBUG
        , m_nDropped(0)
#endif
        {
            try {
                cout << "pcap active" << endl;
                m_pcap.activate();
                m_pcap.setPacketFilter("ether proto \\ip");

                m_pcap_out.activate();
                cout << "assign pcap fd: " << m_pcap_out.getFd() << endl;
                m_socket.assign(m_pcap.getFd());
                m_socket_out.assign(m_pcap_out.getFd());
            } catch (const PcapHelper::Error &e) {
                BOOST_THROW_EXCEPTION(Error(e.what()));
            }

//            /**
//             * 监听网络接口的状态
//             */
//            m_netifStateConn = localEndpoint.onStateChanged.connect(
//                    [=](ndn::net::InterfaceState, ndn::net::InterfaceState newState) {
//                        handleNetifStateChange(newState);
//                    });

            /**
             * 开始异步读取网络接口到来的流
             */
            asyncRead();
        }

        void
        EthernetTransport::doClose() {
//            NFD_LOG_FACE_TRACE(__func__);

            if (m_socket.is_open()) {
                // Cancel all outstanding operations and close the socket.
                // Use the non-throwing variants and ignore errors, if any.
                boost::system::error_code error;
                m_socket.cancel(error);
                m_socket.close(error);
            }
            m_pcap.close();
            m_pcap_out.close();
//            // Ensure that the Transport stays alive at least
//            // until all pending handlers are dispatched
//            getGlobalIoService().post([this] {
//                this->setState(TransportState::CLOSED);
//            });
        }

        void
        EthernetTransport::handleNetifStateChange(ndn::net::InterfaceState netifState) {
            cout << "网络状态改变： " << netifState << endl;
//            NFD_LOG_FACE_TRACE("netif is " << netifState);
//            if (netifState == ndn::net::InterfaceState::RUNNING) {
//                if (getState() == TransportState::DOWN) {
//                    this->setState(TransportState::UP);
//                }
//            }
//            else if (getState() == TransportState::UP) {
//                this->setState(TransportState::DOWN);
//            }
        }

        void
        EthernetTransport::doSend(Packet &&packet) {
//            NFD_LOG_FACE_TRACE(__func__);

//            sendPacket(packet.packet);
        }


        void
        EthernetTransport::sendPacket(const uint8_t *payload, size_t length) {
            vector<uint8_t> bufDstAddress(m_destAddress.data(), m_destAddress.data() + m_destAddress.size());
            vector<uint8_t> bufSrcAddress(m_srcAddress.data(), m_srcAddress.data() + m_srcAddress.size());
//            uint16_t ethertype = htons(0x0800);
//            vector<uint8_t> bufEtherType(reinterpret_cast<const uint8_t *>(&ethertype),
//                                         reinterpret_cast<const uint8_t *>(&ethertype) + 2);
            vector<uint8_t> bufIP(payload, payload + length);

            bufDstAddress.insert(bufDstAddress.end(), bufSrcAddress.begin(), bufSrcAddress.end());
//            bufDstAddress.insert(bufDstAddress.begin(), bufEtherType.begin(), bufEtherType.end());
            bufDstAddress.insert(bufDstAddress.end(), bufIP.begin(), bufIP.end());

            int sent = pcap_inject(m_pcap_out.getPcap(), bufDstAddress.data(), bufDstAddress.size());

            cout << m_srcAddress.toString() << " -> " << m_destAddress.toString() << endl;
            cout << "Successfully sent: " << sent << " bytes(" << bufDstAddress.size() << ")" << endl;

//            ndn::EncodingBuffer buffer(block);
//            // pad with zeroes if the payload is too short
//            if (block.size() < ethernet::MIN_DATA_LEN) {
//                static const uint8_t padding[ethernet::MIN_DATA_LEN] = {};
//                buffer.appendByteArray(padding, ethernet::MIN_DATA_LEN - block.size());
//            }
//
//            // construct and prepend the ethernet header
//            uint16_t ethertype = boost::endian::native_to_big(0x0800);
//            buffer.prependByteArray(reinterpret_cast<const uint8_t *>(&ethertype), ethernet::TYPE_LEN);
//            buffer.prependByteArray(m_srcAddress.data(), m_srcAddress.size());
//            buffer.prependByteArray(m_destAddress.data(), m_destAddress.size());
//
//            // send the frame
//            int sent = pcap_inject(m_pcap_out.getPcap(), buffer.buf(), buffer.size());
//            if (sent < 0)
//                handleError("Send operation failed: " + m_pcap_out.getLastError());
//            else if (static_cast<size_t>(sent) < buffer.size())
//                handleError("Failed to send the full frame: size=" + to_string(buffer.size()) +
//                            " sent=" + to_string(sent));
//            else
//                cout << "Successfully sent: " << buffer.size() << " bytes" << endl;
            // print block size because we don't want to count the padding in buffer
//                NFD_LOG_FACE_TRACE("Successfully sent: " << block.size() << " bytes");
        }

        void
        EthernetTransport::asyncRead() {

            cout << endl << "start: " << m_pcap.getCurTime() << endl;
            m_socket.async_read_some(boost::asio::null_buffers(),
                                     [this](const auto &e, auto) { this->handleRead(e); });
            cout << "end: " << m_pcap.getCurTime() << endl;
        }

        struct timespec sleepTime{
                0, 50
        };

        void
        EthernetTransport::handleRead(const boost::system::error_code &error) {
            if (error) {
                cout << "error: " << error;
                return;
            }

            // 只用async read, 还是用Raw Socket 发包，速率没有提升
//            auto res = m_pcap.readNextPacketAfterDecode();
//            auto tuple = (tuple_p) std::get<0>(res);
//            if (tuple != nullptr) {
//                uint32_t dip = ntohl(tuple->key.dst_ip);
//                string dstIP = to_string((dip >> 24) & 0xFF);
//                dstIP.append(".");
//                dstIP.append(to_string((dip >> 16) & 0xFF));
//                dstIP.append(".");
//                dstIP.append(to_string((dip >> 8) & 0xFF));
//                dstIP.append(".");
//                dstIP.append(to_string((dip >> 0) & 0xFF));
//                rawSocketHelper.sendPacketTo(tuple->pkt, tuple->size, dstIP);
//                nanosleep(&sleepTime, nullptr);
//            }
//            delete tuple;
//            asyncRead();
//
//            return;

            const uint8_t *pkt;
            size_t len;
            std::string err;
            std::tie(pkt, len, err) = m_pcap.readNextPacket();
//            receivePayload(pkt, len);

            if (pkt != nullptr) {
                const ether_header *eh;
                std::tie(eh, err) = checkFrameHeader(pkt, len, m_srcAddress,
                                                     m_destAddress.isMulticast() ? m_destAddress : m_srcAddress);
                if (eh != nullptr) {
//                    ethernet::Address sender(eh->ether_shost);
                    //保留以太网类型，只修改原地址和目的地址
                    pkt += (ethernet::HDR_LEN - 2);
                    len -= (ethernet::HDR_LEN - 2);
                    receivePayload(pkt, len);
                }
            }

#ifdef _DEBUG
            size_t nDropped = m_pcap.getNDropped();
            if (nDropped - m_nDropped > 0)
            NFD_LOG_FACE_DEBUG("Detected " << nDropped - m_nDropped << " dropped frame(s)");
            m_nDropped = nDropped;
#endif

            asyncRead();
        }

        void
        EthernetTransport::receivePayload(const uint8_t *payload, size_t length) {
            sendPacket(payload, length);
        }

        void
        EthernetTransport::handleError(const std::string &errorMessage) {
//            if (getPersistency() == ndn::nfd::FACE_PERSISTENCY_PERMANENT) {
//                NFD_LOG_FACE_DEBUG("Permanent face ignores error: " << errorMessage);
//                return;
//            }
//
//            NFD_LOG_FACE_ERROR(errorMessage);
//            this->setState(TransportState::FAILED);
            cerr << "ERROR: " << errorMessage << endl;
            doClose();
        }

    }
}