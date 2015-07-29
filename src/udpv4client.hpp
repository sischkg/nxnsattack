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
        std::string destination_address;
        uint16_t    destination_port;
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

        uint16_t sendPacket( const uint8_t *data, uint16_t size );
        uint16_t sendPacket( const uint8_t *begin, const uint8_t *end )
        {
            sendPacket( begin, end - begin );
        }
        uint16_t sendPacket( const std::vector<uint8_t> &packet )
        {
            sendPacket( packet.data(), packet.size() );
        }

        PacketInfo receivePacket( bool is_nonblocking = false );
        bool isReadable();
    };


    class Sender
    {
    public:
	typedef boost::shared_ptr<ChecksumCalculatable> ChecksumPtr;
    private:
        int raw_socket;
	ChecksumPtr udp_checksum;

        void openSocket();
        void closeSocket();
    public:
        Sender( ChecksumPtr checksum = ChecksumPtr( new StandardChecksumCalculator() ) )
            : raw_socket( -1 ), udp_checksum( checksum )
        {
            openSocket();
        }

        ~Sender()
        {
            closeSocket();
        }

        uint16_t sendPacket( const PacketInfo & );
    };


    class Receiver
    {
    private:
        int udp_socket;
	std::string bind_address;
        uint16_t bind_port;

        void openSocket();
        void closeSocket();
    public:
        Receiver( uint16_t port )
            : udp_socket( -1 ), bind_address( "0.0.0.0" ), bind_port( port )
        {
            openSocket();
        }

        Receiver( const std::string &bind_addr, uint16_t port )
            : udp_socket( -1 ), bind_address( bind_addr ), bind_port( port )
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
