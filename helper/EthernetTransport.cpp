//
// Created by mingj on 19-1-3.
//

#include "EthernetTransport.hpp"


namespace IP_NDN_STACK {
    namespace pcap {


        EthernetTransport::Packet::Packet(Block &&packet1)
                : packet(std::move(packet1)), remoteEndpoint(0) {}

        EthernetTransport::EthernetTransport(const string &interfaceName, const ethernet::Address &localAddress,
                                             const ethernet::Address &remoteEndpoint, boost::asio::io_service &service)
                : m_socket(service), m_pcap(interfaceName),
                  m_srcAddress(localAddress), m_destAddress(remoteEndpoint),
                  m_interfaceName(interfaceName), m_hasRecentlyReceived(false)
#ifdef _DEBUG
        , m_nDropped(0)
#endif
        {
            try {
                cout << "pcap active" << endl;
                m_pcap.activate();
                cout << "assign pcap fd" << m_pcap.getFd() << endl;
                m_socket.assign(m_pcap.getFd());
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

            sendPacket(packet.packet);
        }


        void
        EthernetTransport::sendPacket(const ndn::Block &block) {
            ndn::EncodingBuffer buffer(block);

            // pad with zeroes if the payload is too short
            if (block.size() < ethernet::MIN_DATA_LEN) {
                static const uint8_t padding[ethernet::MIN_DATA_LEN] = {};
                buffer.appendByteArray(padding, ethernet::MIN_DATA_LEN - block.size());
            }

            // construct and prepend the ethernet header
            uint16_t ethertype = boost::endian::native_to_big(ethernet::ETHERTYPE_NDN);
            buffer.prependByteArray(reinterpret_cast<const uint8_t *>(&ethertype), ethernet::TYPE_LEN);
            buffer.prependByteArray(m_srcAddress.data(), m_srcAddress.size());
            buffer.prependByteArray(m_destAddress.data(), m_destAddress.size());

            // send the frame
            int sent = pcap_inject(m_pcap.getPcap(), buffer.buf(), buffer.size());
            if (sent < 0)
                handleError("Send operation failed: " + m_pcap.getLastError());
            else if (static_cast<size_t>(sent) < buffer.size())
                handleError("Failed to send the full frame: size=" + to_string(buffer.size()) +
                            " sent=" + to_string(sent));
            else
                cout << "Successfully sent: " << block.size() << " bytes" << endl;
            // print block size because we don't want to count the padding in buffer
//                NFD_LOG_FACE_TRACE("Successfully sent: " << block.size() << " bytes");
        }

        void
        EthernetTransport::asyncRead() {
            m_socket.async_read_some(boost::asio::null_buffers(),
                                     [this](const auto &e, auto) { this->handleRead(e); });
        }

        void
        EthernetTransport::handleRead(const boost::system::error_code &error) {
            if (error) {
                cout << "error: " << error;
                return;
            }

            const uint8_t *pkt;
            size_t len;
            std::string err;
            std::tie(pkt, len, err) = m_pcap.readNextPacket();

            if (pkt != nullptr) {
                const ether_header *eh;
                std::tie(eh, err) = checkFrameHeader(pkt, len, m_srcAddress,
                                                     m_destAddress.isMulticast() ? m_destAddress : m_srcAddress);
                if (eh != nullptr) {
                    ethernet::Address sender(eh->ether_shost);
                    pkt += ethernet::HDR_LEN;
                    len -= ethernet::HDR_LEN;
                    receivePayload(pkt, len, sender);
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
        EthernetTransport::receivePayload(const uint8_t *payload, size_t length,
                                          const ethernet::Address &sender) {
//            NFD_LOG_FACE_TRACE("Received: " << length << " bytes from " << sender);
            bool isOk = false;
            Block element;
            std::tie(isOk, element) = Block::fromBuffer(payload, length);
            if (!isOk) {
                cout << "not ok" << endl;
//                NFD_LOG_FACE_WARN("Failed to parse incoming packet from " << sender);
                // This packet won't extend the face lifetime
                return;
            }
            m_hasRecentlyReceived = true;

            Packet tp(std::move(element));
            static_assert(sizeof(tp.remoteEndpoint) >= ethernet::ADDR_LEN,
                          "Transport::Packet::remoteEndpoint is too small");
            if (m_destAddress.isMulticast()) {
                std::memcpy(&tp.remoteEndpoint, sender.data(), sender.size());
            }
            cout << "receive from " <<  sender.toString() << ": " << length << endl;
            cout << element.value_size() << endl;
            cout << tp.packet.value_size() << endl;
            // 发送到目的主机
            sendPacket(tp.packet);
//            this->receive(std::move(tp));
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