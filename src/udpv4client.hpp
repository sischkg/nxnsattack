#ifndef UDPV4CLIENT_HPP
#define UDPV4CLIENT_HPP

#include <string>
#include <boost/cstdint.hpp>
#include <vector>
#include "udpv4.hpp"

namespace udpv4
{

    struct ClientParameters
    {
        std::string     destination_address;
        boost::uint16_t destination_port;
    };


    class Client
    {
    private:
        ClientParameters parameters;
        int udp_socket;

        void openSocket();
        void closeSocket();
    public:
        Client( const ClientParameters &param )
            : parameters( param ), udp_socket( -1 )
        {}

        ~Client();

        boost::uint16_t sendPacket( const boost::uint8_t *data, boost::uint16_t size );
        boost::uint16_t sendPacket( const boost::uint8_t *begin, const boost::uint8_t *end )
        {
            sendPacket( begin, end - begin );
        }
        boost::uint16_t sendPacket( const std::vector<boost::uint8_t> &packet )
        {
            sendPacket( packet.data(), packet.size() );
        }

        PacketInfo receivePacket( bool is_nonblocking = false );
        bool isReadable();
    };


    class Sender
    {
    private:
        int raw_socket;

        void openSocket();
        void closeSocket();
    public:
        Sender()
            : raw_socket( -1 )
        {
            openSocket();
        }

        ~Sender()
        {
            closeSocket();
        }

        boost::uint16_t sendPacket( const PacketInfo & );
    };


    class Receiver
    {
    private:
        int udp_socket;
        boost::uint16_t bind_port;

        void openSocket();
        void closeSocket();
    public:
        Receiver( boost::uint16_t port )
            : udp_socket( -1 ), bind_port( port )
        {
            openSocket();
        }

        ~Receiver()
        {
            closeSocket();
        }

        PacketInfo receivePacket();

        bool isReadable();
    };

}

#endif
