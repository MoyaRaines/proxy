#ifndef _PROXY_SERVER_
#define _PROXY_SERVER_

#include <iostream>
#include <unordered_map>
#include "../pool/io_context_thread_pool.hpp"
#include "../net/tcp_session.hpp"

enum {
    PROXY_AUTH_SUCCESS = 0,
    PROXY_AUTH_FAILED,
    PROXY_AUTH_NONE,
    PROXY_AUTH_ILLEGAL,
};

class ProxyServer{
public:
    ProxyServer(boost::asio::io_context& io_context, short port);

    static bool validateUserNamePassword(std::string user_name, std::string password);
    static int http_authorization(std::string_view proxy_auth);

    static void addUserNameAndPassword(std::string user_name, std::string password);

    static bool getAccountValidateEnableStatus();

    void setProxyPassBy(std::string host, std::string port, std::string user_name, std::string password);

private:
    void asyncAcceptClient();
    void asyncReadOneByte(std::shared_ptr<TcpSession> TcpSession);
private:
    boost::asio::ip::tcp::acceptor m_acceptor;
    inline static std::unordered_map<std::string, std::string> m_account;
};



#endif