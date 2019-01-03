//
// Created by mingj on 19-1-3.
//

#ifndef PCAP_RAW_SOCKET_ETHERNETTRANSPORT_H
#define PCAP_RAW_SOCKET_ETHERNETTRANSPORT_H

#include "common.hpp"
#include "EthernetProtocol.hpp"
#include "PcapHelper.h"
#include <ndn-cxx/net/network-interface.hpp>
#include <ndn-cxx/net/network-monitor.hpp>
#include <cstring> // for memcpy()
#include <boost/thread/tss.hpp>
#include <boost/endian/conversion.hpp>

using namespace nfd;
using namespace IP_NDN_STACK::pcap;
namespace IP_NDN_STACK {
    namespace pcap {

        class EthernetTransport {
        public:
            EthernetTransport(const string  &localEndpoint, const ethernet::Address &localAddress,
                              const ethernet::Address &remoteEndpoint, boost::asio::io_service &service);

            class Error : public std::runtime_error {
            public:
                explicit
                Error(const std::string &what)
                        : std::runtime_error(what) {
                }
            };

            typedef uint64_t EndpointId;

            class Packet {
            public:
                Packet() = default;

                explicit
                Packet(Block &&packet);

            public:
                /** \brief the packet as a TLV block
                 */
                Block packet;

                /** \brief identifies the remote endpoint
                 *
                 *  This ID is only meaningful in the context of the same Transport.
                 *  Incoming packets from the same remote endpoint have the same EndpointId,
                 *  and incoming packets from different remote endpoints have different EndpointIds.
                 */
                EndpointId remoteEndpoint;
            };

            /**
            * @brief Processes the payload of an incoming frame
            * @param payload Pointer to the first byte of data after the Ethernet header
            * @param length Payload length
            * @param sender Sender address
            */
            void
            receivePayload(const uint8_t *payload, size_t length,
                           const ethernet::Address &sender);

        protected:


            void
            doClose();


            bool
            hasRecentlyReceived() const {
                return m_hasRecentlyReceived;
            }

            void
            resetRecentlyReceived() {
                m_hasRecentlyReceived = false;
            }

        private:
            void
            handleNetifStateChange(ndn::net::InterfaceState netifState);

            void
            doSend(Packet &&packet);

            /**
             * @brief Sends the specified TLV block on the network wrapped in an Ethernet frame
             */
            void
            sendPacket(const ndn::Block &block);

            void
            asyncRead();

            void
            handleRead(const boost::system::error_code &error);

            void
            handleError(const std::string &errorMessage);

        protected:
            boost::asio::posix::stream_descriptor m_socket;
            PcapHelper m_pcap;
            ethernet::Address m_srcAddress;
            ethernet::Address m_destAddress;
            std::string m_interfaceName;

        private:
            ndn::util::signal::ScopedConnection m_netifStateConn;
            bool m_hasRecentlyReceived;
#ifdef _DEBUG
            /// number of frames dropped by the kernel, as reported by libpcap
  size_t m_nDropped;
#endif
        };


    }
}

#endif //PCAP_RAW_SOCKET_ETHERNETTRANSPORT_H