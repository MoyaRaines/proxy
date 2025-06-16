#ifndef _Socks5Proxy_H_
#define _Socks5Proxy_H_

#include <spdlog/spdlog.h>

#include "../net/tcp_session.hpp"
#include "../net/io_copy.hpp"

#include "../pool/io_context_thread_pool.hpp"

#include "socks_enmus.h"
#include "proxy_server.h"

/* Socks5 TCP:
    client                     proxy                   target
    |    --- auth request --->   |                        |
    |     <--- auth reply ---    |                        |
    |                            |                        |
    |  --- U/P negotiation --->  |                        |
    |    <--- U/P reply ---      |                        |
    |                            |                        |
    |   --- proxy request --->   |                        |
    |                            |    --- connect --->    |
    |                            |    <--- response ---   |
    |    <--- response ---       |                        |
    |                            |                        |
    |       <-------->        IO Copy     <-------->      |
    |                            |                        |
    |       <-------->          End       <-------->      |
*/

class Socks5Proxy : public IOCopy{
public:
    Socks5Proxy(std::shared_ptr<TcpSession> tcpSession){
        m_client_auth.resize(1024, '\0');
        m_client_username_password_negotiation.resize(1024, '\0');
        m_client_proxy_request.resize(1024, '\0');

        m_client = tcpSession;
        m_target = TcpSession::Create(tcpSession->getIOContext());

        receiveClientAuthRequest();
    }

    ~Socks5Proxy(){
        spdlog::trace("Socks5Proxy destroy.");
    }

    /* Client auth request: 
        +----+----------+----------+
        |VER | NMETHODS | METHODS  |
        +----+----------+----------+
        | 1  |    1     | 1 to 255 |
        +----+----------+----------+
        VER: protocol version(0x05)
        NMETHODS: 
            0x00: NO AUTHENTICATION REQUIRED
            0x01: GSSAPI        
            0x02: USERNAME/PASSWORD    
            0x03: IANA ASSIGNED
            0x80-0xfe: RESERVED FOR PRIVATE METHODS      
            0xff: NO ACCEPTABLE METHODS
        METHODS: identifier 
    */
    void receiveClientAuthRequest(){
        m_client->asyncReadSomeData(m_client_auth.data(), m_client_auth.size(), [this](const boost::system::error_code& ec, std::size_t bytes_transferred){
            if(!ec){
                spdlog::trace("Receive client socks5 auth success. {} bytes transferred.", bytes_transferred);

                int n_methods = uint8_t(m_client_auth[1]);
                uint8_t method_server_select;
                if (n_methods <= 0 || n_methods > 255){
                    if(ProxyServer::getAccountValidateEnableStatus()){
                        method_server_select = SOCKS5_AUTH;
                    }else{
                        method_server_select = SOCKS5_AUTH_NONE;
                    }
                }else{
                    method_server_select = SOCKS5_AUTH_UNACCEPTABLE;
                }
                replyClientAuthRequest(method_server_select);
            }else{
                spdlog::trace("Receive client socks5 auth request failed, error: {}", ec.message());
                delete this;
            }
        });
    }

/*
    Server Auth Reply:
        +----+--------+
        |VER | METHOD |
        +----+--------+
        | 1  |   1    |
        +----+--------+
        VER: protocol version(0x05)
        METHOD: 
            0x00: NO AUTHENTICATION REQUIRED
            0x01: GSSAPI
            0x02: USERNAME/PASSWORD
            0x03 - 0x7F: IANA ASSIGNED
            0x80 - 0xFE: RESERVED FOR PRIVATE METHODS
            0xFF: NO ACCEPTABLE METHODS
*/
    void replyClientAuthRequest(uint8_t method_server_select){
        std::vector<unsigned char> auth_reply;
        auth_reply.push_back(SOCKS_VERSION_5);
        auth_reply.push_back(method_server_select);

        m_client->asyncWriteData(reinterpret_cast<const char*>(auth_reply.data()), auth_reply.size(), [this](const boost::system::error_code& ec, const size_t& byte_transferred){
            if(!ec){
                spdlog::trace("Reply client socks5 auth success. {} bytes transferred.", byte_transferred);

                if(ProxyServer::getAccountValidateEnableStatus()){
                    receiveClientUserNamePasswordNegotiation();
                }else{
                    receiveClientProxyRequest();
                }
            }else{
                spdlog::trace("Reply client socks5 auth failed, error message: {}", ec.message());
                delete this;
            }
        });
    }

/*  Client Username/Password subnegotiation request: 
        +----+------+----------+------+----------+
        |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
        +----+------+----------+------+----------+
        | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
        +----+------+----------+------+----------+
        VER: The current version of the subnegotiation(0x01).
        ULEN: The length of the UNAME field that follows.
        UNAME: Username. 
        PLEN: The length of the PASSWD field that follows.
        PASSWD: The password association with the given UNAME.
*/
    void receiveClientUserNamePasswordNegotiation(){
        m_client->asyncReadSomeData(m_client_username_password_negotiation.data(), m_client_username_password_negotiation.size(), [this](const boost::system::error_code& ec, std::size_t bytes_transferred){
            if (!ec) {
                spdlog::trace("Receive client socks5 U/P negotiation success. {} bytes transferred.", bytes_transferred);

                uint8_t* data = reinterpret_cast<uint8_t*>(m_client_username_password_negotiation.data());
                
                if (bytes_transferred < 2) {        // Read     ver(1)  ulen(1)
                    replyClientUsernamePasswordNegotiation(false);
                }
                uint8_t ver = data[0];
                uint8_t ulen = data[1];
                

                if (bytes_transferred < 2 + ulen + 1) {     // Read     ver(1)   ulen(1)   UNAME(ulen)   plen(1)
                    replyClientUsernamePasswordNegotiation(false);
                }
                std::string user_name(reinterpret_cast<char*>(data + 2), ulen);
                uint8_t plen = data[2 + ulen];


                if (bytes_transferred < 2 + ulen + 1 + plen) {  // Read     ver(1)   ulen(1)   UNAME(ulen)   plen(1)   password(plen)
                    replyClientUsernamePasswordNegotiation(false);
                }
                std::string password(reinterpret_cast<char*>(data + 3 + ulen), plen);

                // Validate account and reply.
                bool valid = ProxyServer::validateUserNamePassword(user_name, password);
                spdlog::trace("Validate username and password {}:{} {}", user_name, password, valid);
                replyClientUsernamePasswordNegotiation(valid);

            } else {
                spdlog::trace("Receive client socks5 U/P negotiation failed, error: {}", ec.message());
                delete this;
            }
        });
    }

/*  Server Username/Password subnegotiation reply.
        +----+--------+
        |VER | STATUS |
        +----+--------+
        | 1  |   1    |
        +----+--------+
        VER: The current version of the subnegotiation(0x01).
        STATUS: 
            0x00: Success
            Value other than 0x00: Failed. Client must close the connection.
*/
    void replyClientUsernamePasswordNegotiation(bool valid){
        std::vector<unsigned char> negotiation_reply = {0x01};
        if(valid){
            negotiation_reply.push_back(0x00);
        }else{
            negotiation_reply.push_back(0x01);
        }

        m_client->asyncWriteData(reinterpret_cast<const char*>(negotiation_reply.data()), negotiation_reply.size(), [this, valid](const boost::system::error_code& ec, std::size_t bytes_transferred){
            if(!ec){
                spdlog::trace("Reply client socks5 U/P negotiation success. {} bytes transferred.", bytes_transferred);

                if(!valid){
                    delete this;
                }else{
                    receiveClientProxyRequest();
                }
            }else{
                spdlog::trace("Reply client socks5 U/P negotiation failed, error: {}", ec.message());
                delete this;
            }
        });
    }

/*  Client Proxy Request: 
        +----+-----+-------+------+----------+----------+
        |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  | X'00' |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+
        VER: protocol version
        CMD: 
            0x01: CONNECT
            0x02: BIND
            0x03: UDP ASSOCIATE
        RSV: RESERVED
        ATYP: address type of following address
            0x01: IP V4 address
            0x03: DOMAINNAME
            0x04: IP V6 address
        DST.ADDR: desired destination address
        DST.PORT: desired destination port in network octet order
*/
    void receiveClientProxyRequest(){
        m_client->asyncReadSomeData(m_client_proxy_request.data(), m_client_proxy_request.size(), [this](const boost::system::error_code& ec, std::size_t bytes_transferred){
            if(!ec){
                spdlog::trace("Receive client socks5 proxy request success. {} bytes transferred.", bytes_transferred);

                uint8_t* data = reinterpret_cast<uint8_t*>(m_client_proxy_request.data());
                uint8_t ver = data[0];
                uint8_t cmd = data[1];
                uint8_t rsv = data[2];
                uint8_t atyp = data[3];
            
                std::string target_address;
                uint16_t target_port = 0;
            
                switch (atyp) {
                    case SOCKS5_ATYP_IPV4:
                        if (bytes_transferred < 9) {
                            spdlog::trace("Incomplete IPv4 address in SOCKS5 request");
                            return;
                        }
                        struct in_addr ipv4_addr;
                        std::memcpy(&ipv4_addr, data + 4, sizeof(ipv4_addr));
                        char ip_str[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &ipv4_addr, ip_str, INET_ADDRSTRLEN);
                        target_address = ip_str;
                        target_port = (data[8] << 8) | data[9];
                        break;
            
                    case SOCKS5_ATYP_DOMAINNAME: 
                        if (bytes_transferred < 5 + data[4]) {
                            spdlog::trace("Incomplete domain name in SOCKS5 request");
                            return;
                        }
                        target_address = std::string(data + 5, data + 5 + data[4]);
                        target_port = (data[5 + data[4]] << 8) | data[6 + data[4]];
                        break;
            
                    case SOCKS5_ATYP_IPV6:
                        if (bytes_transferred < 19) {
                            spdlog::trace("Incomplete IPv6 address in SOCKS5 request");
                            return;
                        }
                        struct in6_addr ipv6_addr;
                        std::memcpy(&ipv6_addr, data + 4, sizeof(ipv6_addr));
                        char ip6_str[INET6_ADDRSTRLEN];
                        inet_ntop(AF_INET6, &ipv6_addr, ip6_str, INET6_ADDRSTRLEN);
                        target_address = ip6_str;
                        target_port = (data[18] << 8) | data[19];
                        break;
                    default:
                        spdlog::trace("Unsupported address type in SOCKS5 request: {}", atyp);
                        return;
                }

                spdlog::trace("Target address: {} Target port: {}", target_address, target_port);
                m_target_host = target_address;

                if(cmd == SOCKS_CMD_CONNECT){
                    establishConnectionToTarget(target_address, target_port);
                }else if(cmd == SOCKS5_CMD_UDP){
                    // TODO: UDP Support
                    replyClientProxyRequest(0x07);      // 0x07: Command not supported
                }else{
                    replyClientProxyRequest(0x07);      // 0x07: Command not supported
                }
            }else{
                spdlog::trace("Receive client socks5 proxy request failed, error: {}", ec.message());
                delete this;
            }
        });
    }


    virtual void establishConnectionToTarget(std::string target_address, int target_port){
        m_target->asyncConnectToHost(target_address, target_port, [this](const int code, const std::string err_message){
            if (!code) {
                setTargetConnectStatusAndGoOn(SOCKS5_SUCCEEDED);
                spdlog::trace("Target connect success.");
            }
            else {
                uint8_t socks_error_code;
                if (code == boost::asio::error::connection_refused)
                    socks_error_code = SOCKS5_CONNECTION_REFUSED;
                else if (code == boost::asio::error::network_unreachable)
                    socks_error_code = SOCKS5_NETWORK_UNREACHABLE;
                else if (code == boost::asio::error::host_unreachable)
                    socks_error_code = SOCKS5_HOST_UNREACHABLE;
                else
                    socks_error_code = SOCKS5_GENERAL_SOCKS_SERVER_FAILURE;
                setTargetConnectStatusAndGoOn(socks_error_code);
                spdlog::trace("Target connect failed.");
            }
        });
    }

    void setTargetConnectStatusAndGoOn(uint8_t error_code, boost::asio::ip::tcp::socket* target_socket = nullptr){
        replyClientProxyRequest(error_code);
    }

/*
    Reply Client Proxy Request:
        +----+-----+-------+------+----------+----------+
        |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  | X'00' |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+
        VER: protocol version
        REP: reply field
            0x00: succeeded
            0x01: general SOCKS server failure
            0x02: connection not allowed by ruleset
            0x03: Network unreachable
            0x04: Host unreachable
            0x05: Connection refused
            0x06: TTL expired
            0x07: Command not supported
            0x08: Address type not supported
            0x09 - 0xFF: unassigned
        RSV: RESERVED (Must be set to 0x00)
        ATYP: address type of following address
            0x01: IP V4 address
            0x03: DOMAINNAME
            0x04: IP V6 address
        BND.ADDR: server bound address
        BND.PORT: server bound port in network octet order
*/
    void replyClientProxyRequest(uint8_t error_code){
        std::vector<unsigned char> proxy_request_reply;
        proxy_request_reply.push_back(SOCKS_VERSION_5);     // Ver
        proxy_request_reply.push_back(error_code);          // REP
        proxy_request_reply.push_back(0x00);                // RSV

        if (m_target->getPeerIPAddress().is_v4()) {
            boost::asio::ip::address_v4 ipv4_address = m_target->getPeerIPAddress().to_v4();
        
            proxy_request_reply.push_back(SOCKS5_ATYP_IPV4);    // ATYP 
            
            // IPv4 - 32bit(4bytes)
            uint8_t ipv4_bytes[4];      
            std::copy(ipv4_address.to_bytes().begin(), ipv4_address.to_bytes().end(), ipv4_bytes);
            proxy_request_reply.insert(proxy_request_reply.end(), ipv4_bytes, ipv4_bytes + 4);    // BND.ADDR
        } else if (m_target->getPeerIPAddress().is_v6()) {
            boost::asio::ip::address_v6 ipv6_address = m_target->getPeerIPAddress().to_v6();
        
            proxy_request_reply.push_back(SOCKS5_ATYP_IPV6);    // ATYP
            
            // IPv6 - 128bit(16bytes)
            uint8_t ipv6_bytes[16];      
            std::copy(ipv6_address.to_bytes().begin(), ipv6_address.to_bytes().end(), ipv6_bytes);
            proxy_request_reply.insert(proxy_request_reply.end(), ipv6_bytes, ipv6_bytes + 16);    // BND.ADDR
        } else {
            delete this;
            return;
        }

        uint16_t port = m_target->getPeerPort();
        proxy_request_reply.push_back(static_cast<uint8_t>((port >> 8) & 0xFF));    // BND.PORT
        proxy_request_reply.push_back(static_cast<uint8_t>(port & 0xFF));

        m_client->asyncWriteData(reinterpret_cast<const char*>(proxy_request_reply.data()), proxy_request_reply.size(), [this, error_code](const boost::system::error_code& ec, std::size_t bytes_transferred){
            if(!ec){
                spdlog::trace("Reply client proxy request success. {} bytes", bytes_transferred);

                if(error_code == SOCKS5_SUCCEEDED){
                    startIOCopy(m_client, m_target, 65535);
                }else{
                    delete this;
                }
            }else{
                spdlog::trace("Reply client proxy request failed, error: {}", ec.message());
                delete this;
            }
        });
    }


    void onIOCopyFinished() override {
        spdlog::info("Proxy server: socks5 {} ({} <--> {})  {} bytes / {} s.", m_target_host,  m_client->getRemoteAddressAndPort(), m_target->getRemoteAddressAndPort(), m_bytes_transferred, std::difftime(m_end_time, m_start_time));
        delete this;
    }

    void startUDPIOCopy(){
        
    }

    std::shared_ptr<TcpSession> m_client;
    std::shared_ptr<TcpSession> m_target;

    std::string m_target_host;
    std::vector<char> m_client_auth;
    std::vector<char> m_client_username_password_negotiation;
    std::vector<char> m_client_proxy_request;
};


#endif 