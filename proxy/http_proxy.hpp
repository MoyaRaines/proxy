#ifndef _HTTP_PROXY_
#define _HTTP_PROXY_

#include <boost/asio.hpp>
#include <boost/beast.hpp>

#include <spdlog/spdlog.h>

#include "../net/tcp_session.hpp"
#include "../net/io_copy.hpp"

#include "../pool/io_context_thread_pool.hpp"
#include "../utils/url.hpp"

#include "proxy_server.h"
#include "socks_enmus.h"

namespace beast = boost::beast;			// from <boost/beast.hpp>
namespace http = beast::http;           // from <boost/beast/http.hpp>
using string_body = http::string_body;
using string_request = http::request<string_body>;
using request_parser = http::request_parser<string_request::body_type>;


class HttpProxy : public IOCopy{
public:
    HttpProxy(std::shared_ptr<TcpSession> tcpSession, uint8_t proto_byte){
        m_proto_byte = proto_byte;
        m_client = tcpSession;
        m_target = TcpSession::Create(tcpSession->getIOContext());
        receiveClientAuthRequest();
    }

    ~HttpProxy(){
    
    }

    void receiveClientAuthRequest(){
        // 之前读取的1byte，再写到缓冲区里面
        auto ptr = m_request_buffer.prepare(sizeof(m_proto_byte));
        *reinterpret_cast<uint8_t*>(ptr.data()) = m_proto_byte;
        m_request_buffer.commit(sizeof(m_proto_byte));

        m_client->asyncReadHttpRequest(m_request_buffer, m_request, [this](const boost::system::error_code& ec, std::size_t bytes_transferred){
            if(!ec){
                if(m_proto_byte != 0x43){       // != C
                    auto method = m_request.method_string();
                    auto target_view = std::string(m_request.target());
                    auto proxy_auth = std::string(m_request[http::field::proxy_authorization]);
                    auto keep_alive = m_request.keep_alive();

                    spdlog::trace("method: {} target_view: {} proxy_auth: {}", method, target_view, proxy_auth);

                    int status = ProxyServer::http_authorization(proxy_auth);
                    
                    const auto authority_pos = target_view.find_first_of("//") + 2;

                    const auto scheme_id = URL::string_to_scheme(target_view.substr(0, authority_pos - 3));
                    uint16_t port = URL::scheme_to_default_port(scheme_id);

                    auto host_pos = authority_pos;
                    auto host_end = std::string::npos;

                    auto port_start = std::string::npos;

                    for (auto pos = authority_pos; pos < target_view.size(); pos++)
                    {
                        const auto& c = target_view[pos];
                        if (c == '@')
                        {
                            host_pos = pos + 1;

                            host_end = std::string::npos;
                            port_start = std::string::npos;
                        }
                        else if (c == ':')
                        {
                            host_end = pos;
                            port_start = pos + 1;
                        }
                        else if (c == '/' || (pos + 1 == target_view.size()))
                        {
                            if (host_end == std::string::npos)
                                host_end = pos;
                            m_target_host = target_view.substr(host_pos, host_end - host_pos);

                            if (port_start != std::string::npos)
                                port = (uint16_t)std::atoi(target_view.substr(port_start, pos - port_start).c_str());

                            break;
                        }
                    }
                    establishConnectionToTarget(m_target_host, port);
                }else{
                    auto mth = std::string(m_request.method_string());
                    auto target_view = std::string(m_request.target());
                    auto proxy_auth = std::string(m_request[http::field::proxy_authorization]);

                    int status = ProxyServer::http_authorization(proxy_auth);

                    auto pos = target_view.find(':');
                    if (pos == std::string::npos)       // illegal target
                    {
                        m_target_status = false;
                        replyConnectStatusToClient();
                        return;
                    }

                    m_target_host = std::string(target_view.substr(0, pos));
                    std::string port_string = target_view.substr(pos + 1);
                    int port = (uint16_t)std::atoi(port_string.c_str());
                    establishConnectionToTarget(m_target_host, port);
                }
            }else{
                spdlog::trace("Receive client http auth request failed, error: {}", ec.message());
                delete this;
            }
        });
    }

    void establishConnectionToTarget(std::string target_address, int target_port){
        spdlog::trace("Establish connection to target {}:{}", target_address, target_port);
        m_target->asyncConnectToHost(target_address, target_port, [this](const int code, const std::string err_message){
            if(!code){
                spdlog::trace("Target connect success");
                setTargetConnectStatusAndGoOn(true);
            }else{
                spdlog::trace("Target connect failed, error: {}", err_message);
                setTargetConnectStatusAndGoOn(false);
            }
        });
    }

    void setTargetConnectStatusAndGoOn(bool status){
        m_target_status = status;
        if(m_target_status){
            if(m_proto_byte == 0x43){   // C
                replyConnectStatusToClient();
            }else{
                writeRequestToTarget();
            }
        }else{
            replyConnectStatusToClient();
        }
    }


    void writeRequestToTarget(){
        auto target_view = std::string(m_request.target());
        const auto authority_pos = target_view.find_first_of("//") + 2;
        const auto path_pos = target_view.find_first_of("/", authority_pos);
        if (path_pos == std::string_view::npos){
            m_request.target("/");
        }else{
            m_request.target(std::string(target_view.substr(path_pos)));
        }
        m_request.set(http::field::host, m_target_host);
        if (m_request.find(http::field::connection) == m_request.end() && m_request.find(http::field::proxy_connection) != m_request.end()){
            m_request.set(http::field::connection, m_request[http::field::proxy_connection]);
        }
        m_request.erase(http::field::proxy_authorization);
        m_request.erase(http::field::proxy_connection);

        m_target->asyncWriteHttpData(m_request, [this](const boost::system::error_code& ec, std::size_t bytes_transferred){
            if(!ec){
                spdlog::trace("Write request to target success, {} bytes transferred", bytes_transferred);
                startIOCopy(m_client, m_target, 65535);
            }else{
                spdlog::trace("Write request to target failed, error: {}", ec.message());
            }
        });
    }

    void replyConnectStatusToClient(){
        http::response<http::empty_body> response{ 
            m_target_status ? http::status::ok : http::status::bad_gateway, 
            m_request.version() 
        };

        m_client->asyncWriteHttpData(response, [this](const boost::system::error_code& ec, std::size_t bytes_transferred){
            if(!ec){
                if(m_proto_byte == 0x43 && m_target_status){   // C
                    startIOCopy(m_client, m_target, 65535);
                }else{
                    delete this;
                }

            }else{
                spdlog::trace("Reply connect status failed");
                delete this;
            }
        });
    }

    void onIOCopyFinished() override {
        spdlog::info("Proxy server: http {} {} ({} <--> {})  {} bytes / {} s.", std::string(m_request.method_string()), m_target_host,  m_client->getRemoteAddressAndPort(), m_target->getRemoteAddressAndPort(), m_bytes_transferred, std::difftime(m_end_time, m_start_time));
        delete this;
    }


    // http request
    beast::flat_buffer m_request_buffer{8192};
    http::request<http::dynamic_body> m_request;

    std::shared_ptr<TcpSession> m_client;
    std::shared_ptr<TcpSession> m_target;

    uint8_t m_proto_byte;

    bool m_target_status;
    std::string m_target_host;

    boost::asio::io_context* m_io_context;
};


#endif