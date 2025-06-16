#include "proxy_server.h"
#include "socks5_proxy.hpp"
#include "http_proxy.hpp"
#include "socks4_proxy.hpp"

ProxyServer::ProxyServer(boost::asio::io_context& io_context, short port)
    : m_acceptor(io_context, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port)) {
        spdlog::info("ProxyServer {}:{} start accept client connection.", "localhost", port);
        asyncAcceptClient();
}
 
bool ProxyServer::validateUserNamePassword(std::string user_name, std::string password){
    if(m_account.size() == 0){
        return true;
    }

    auto it = ProxyServer::m_account.find(user_name);
    if (it != ProxyServer::m_account.end()) {
        if (it->second == password) {
            return true;
        } else {
            return false;
        }
    } else {
        return false;
    }
}


int ProxyServer::http_authorization(std::string_view proxy_auth){
    if(m_account.size() == 0){
        return PROXY_AUTH_SUCCESS;
    }

    if (proxy_auth.empty())
        return PROXY_AUTH_NONE;

    auto pos = proxy_auth.find(' ');
    if (pos == std::string::npos)
        return PROXY_AUTH_ILLEGAL;

    auto type = proxy_auth.substr(0, pos);
    auto auth = proxy_auth.substr(pos + 1);

    if (type != "Basic")
        return PROXY_AUTH_ILLEGAL;

    std::string userinfo(
        beast::detail::base64::decoded_size(auth.size()), 0);
    auto [len, _] = beast::detail::base64::decode(
        (char*)userinfo.data(),
        auth.data(),
        auth.size());
    userinfo.resize(len);

    pos = userinfo.find(':');

    std::string uname = userinfo.substr(0, pos);
    std::string passwd = userinfo.substr(pos + 1);
    spdlog::trace("http authorization: {}:{}", uname, passwd);
    auto it = ProxyServer::m_account.find(uname);
    if (it != ProxyServer::m_account.end()) {
        if (it->second == passwd) {
            return PROXY_AUTH_SUCCESS;
        } else {
            return PROXY_AUTH_FAILED;
        }
    } else {
        return PROXY_AUTH_FAILED;
    }
}

void ProxyServer::addUserNameAndPassword(std::string user_name, std::string password){
    m_account[user_name] = password;
}


bool ProxyServer::getAccountValidateEnableStatus(){
    return !m_account.empty();
}


void ProxyServer::asyncAcceptClient() {
    boost::asio::io_context* io_context = IOContextThreadPool::getInstance()->get_io_context();
    std::shared_ptr<TcpSession> tcpSession = TcpSession::Create(io_context);
    m_acceptor.async_accept(*(tcpSession->getTCPSocket()), [this, tcpSession](const boost::system::error_code& ec){
        if (!ec) {
            asyncReadOneByte(tcpSession);
            asyncAcceptClient();
        }
    });
}

void ProxyServer::asyncReadOneByte(std::shared_ptr<TcpSession> tcpSession){
    char* proto = new char[1];
    tcpSession->asyncReadSomeData(proto, 1, [this, tcpSession, proto](const boost::system::error_code& ec, std::size_t bytes_transferred){
        if(!ec){
            const uint8_t proto_byte = *proto;
            if(proto_byte == 0x04){
                new Socks4Proxy(tcpSession);
            }else if (proto_byte == 0x05){ 
                new Socks5Proxy(tcpSession);
            }else if(proto_byte == 0x16){     
                // TODO: Support SSL 
            }else if(proto_byte == 0x47 || proto_byte == 0x50 || proto_byte == 0x43){			// "G" "P" "C"
                new HttpProxy(tcpSession, proto_byte);
            }else{
                spdlog::trace("Unknown protocol.");
            }
        }else{
        }
    });
    delete proto;
}