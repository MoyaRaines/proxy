#ifndef _Socks4Proxy_H_
#define _Socks4Proxy_H_

#include <spdlog/spdlog.h>

#include "../net/tcp_session.hpp"
#include "../net/io_copy.hpp"

#include "../pool/io_context_thread_pool.hpp"

#include "socks_enmus.h"
#include "proxy_server.h"

/* Socks4 TCP:
    client                     proxy                   target
    |    --- auth request --->   |                        |
    |                            |    --- connect --->    |
    |                            |    <--- response ---   |
    |     <--- auth reply ---    |                        |
    |                            |                        |
    |       <-------->        IO Copy     <-------->      |
    |                            |                        |
    |       <-------->          End       <-------->      |
*/


class Socks4Proxy : public IOCopy{
public:
    Socks4Proxy(std::shared_ptr<TcpSession> tcpSession){
        m_client_proxy_request.resize(1024, '\0');
        m_client = tcpSession;
        m_target = TcpSession::Create(tcpSession->getIOContext());
        receiveClientAuthRequest();
    }

    ~Socks4Proxy(){
        spdlog::trace("Socks4Proxy destroy.");
    }

    /* Client auth request: 
        +----+----+----+----+----+----+----+----+----+----+....+----+
        | VN | CD | DSTPORT |      DSTIP        | USERID       |NULL|
        +----+----+----+----+----+----+----+----+----+----+....+----+
        | 1  | 1  |    2    |         4         | variable     | 1  |
        +----+----+----+----+----+----+----+----+----+----+....+----+
        VN: SOCKS protocol version number (should be 4)
        CD: SOCKS command code (should be 1 for CONNECT request)
        NULL: a byte of all zero bits
    */
    void receiveClientAuthRequest(){
        m_client->asyncReadSomeData(m_client_proxy_request.data(), m_client_proxy_request.size(), [this](const boost::system::error_code& ec, std::size_t bytes_transferred){
            if(!ec){
                spdlog::trace("Receive client socks4 auth success. {} bytes transferred.", bytes_transferred);

                uint8_t* data = reinterpret_cast<uint8_t*>(m_client_proxy_request.data());
                // 之前已经读取了一字节
                //uint8_t version = data[0];            // VN: SOCKS协议版本号
                uint8_t command = data[0];              // CD: SOCKS命令代码
                uint16_t destination_port = data[1] << 8 | data[2]; // DSTPORT: 目标端口（大端序）
                uint32_t destination_ip = data[3] << 24 | data[4] << 16 | data[5] << 8 | data[6]; // DSTIP: 目标IP地址（大端序）
                
                struct in_addr ipv4_addr;
                std::memcpy(&ipv4_addr, data + 3, sizeof(ipv4_addr));
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &ipv4_addr, ip_str, INET_ADDRSTRLEN);
                m_target_host = ip_str;
                boost::system::error_code ec;
                boost::asio::ip::address ip_address = boost::asio::ip::make_address(m_target_host, ec);

                bool socks4a = false;
                auto tmp = ip_address.to_v4().to_uint() ^ 0x000000ff;
                if (0xff > tmp)
                    socks4a = true;

                std::string userid;
                size_t index = 7;
                for (index; index < m_client_proxy_request.size(); ++index) {
                    if (data[index] == 0x00 || index == bytes_transferred) {
                        break;
                    }
                    userid += static_cast<char>(data[index]);
                }

                if (socks4a){
                    m_target_host = "";
                    for (index++; index < m_client_proxy_request.size(); ++index) {
                        if (data[index] == 0x00 || index == bytes_transferred) {  
                            break; 
                        }
                        m_target_host += static_cast<char>(data[index]); 
                    }
                }

                m_target_port = destination_port;
                spdlog::trace("Socks4 command:{} target:{} port:{} userid:{}", command, m_target_host, destination_port, userid);


                if(command != SOCKS_CMD_CONNECT){
                    this->replyClientAuthRequest(SOCKS4_REQUEST_REJECTED_OR_FAILED);
                    return;
                }

                // TODO: validate account.
                bool userid_valid = true;
                if(userid_valid){
                    this->establishConnectionToTarget(m_target_host, destination_port);
                }else{
                    
                }

            }else{
                spdlog::trace("Receive client socks4 auth request failed, error: {}", ec.message());
                delete this;
            }
        });
    }

/*
    Server Auth Reply:
        +----+----+----+----+----+----+----+----+
        | VN | CD | DSTPORT |      DSTIP        |
        +----+----+----+----+----+----+----+----+
        | 1  | 1  |    2    |         4         |
        +----+----+----+----+----+----+----+----+
        VN: the version of the reply code (should be 0)
        CD: 
            90: request granted
            91: request rejected or failed
            92: request rejected becasue SOCKS server cannot connect to
                identd on the client
            93: request rejected because the client program and identd
                report different user-ids
*/
    void replyClientAuthRequest(uint8_t cd){
        std::vector<unsigned char> reply;

        reply.push_back(0x00);
        reply.push_back(cd);

        uint16_t port = m_target_port;
        reply.push_back(static_cast<uint8_t>((port >> 8) & 0xFF));    // DSTPORT
        reply.push_back(static_cast<uint8_t>(port & 0xFF));

        // if(cd == SOCKS4_REQUEST_GRANTED){
            if (m_target->getPeerIPAddress().is_v4()) {
                boost::asio::ip::address_v4 ipv4_address = m_target->getPeerIPAddress().to_v4();
            
                // IPv4 - 32bit(4bytes)
                uint8_t ipv4_bytes[4];      
                std::copy(ipv4_address.to_bytes().begin(), ipv4_address.to_bytes().end(), ipv4_bytes);
                reply.insert(reply.end(), ipv4_bytes, ipv4_bytes + 4);    // BND.ADDR
            } else if (m_target->getPeerIPAddress().is_v6()) {
                boost::asio::ip::address_v6 ipv6_address = m_target->getPeerIPAddress().to_v6();

                // IPv6 - 128bit(16bytes)
                uint8_t ipv6_bytes[16];      
                std::copy(ipv6_address.to_bytes().begin(), ipv6_address.to_bytes().end(), ipv6_bytes);
                reply.insert(reply.end(), ipv6_bytes, ipv6_bytes + 16);    // BND.ADDR
            } else {
                delete this;
                return;
            }
        // }else{
            
        // }

        m_client->asyncWriteData(reinterpret_cast<const char*>(reply.data()), reply.size(), [this, cd](const boost::system::error_code& ec, std::size_t bytes_transferred){
            if(!ec){
                spdlog::trace("Reply client success");
                if(cd == SOCKS4_REQUEST_GRANTED){
                    startIOCopy(m_client, m_target, 65535);
                }else{
                    delete this;
                }
            }else{
                delete this;
            }
        });
    }


    virtual void establishConnectionToTarget(std::string target_address, int target_port){
        m_target->asyncConnectToHost(target_address, target_port, [this](const int err_code, const std::string err_message){
            if (!err_code) {
                setTargetConnectStatusAndGoOn(true);
            }else {
                setTargetConnectStatusAndGoOn(false);
            }
        });
    }


    void setTargetConnectStatusAndGoOn(bool target_status, boost::asio::ip::tcp::socket* target_socket = nullptr){
        if(target_status){
            replyClientAuthRequest(SOCKS4_REQUEST_GRANTED);
        }else{
            replyClientAuthRequest(SOCKS4_CANNOT_CONNECT_TARGET_SERVER);
        }
    }


    void onIOCopyFinished() override {
        spdlog::info("Proxy server socks4 {} ({} <--> {})  {} bytes / {} s.", m_target_host,  m_client->getRemoteAddressAndPort(), m_target->getRemoteAddressAndPort(), m_bytes_transferred, std::difftime(m_end_time, m_start_time));
        delete this;
    }

    std::shared_ptr<TcpSession> m_client;
    std::shared_ptr<TcpSession> m_target;

    std::string m_target_host;
    int m_target_port;
    std::vector<char> m_client_proxy_request;
};


#endif 