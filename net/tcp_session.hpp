#pragma once
#ifndef TCPCLIENT_H
#define TCPCLIENT_H

#include <iostream>
#include <functional>

#include <boost/asio.hpp>
#include <boost/system/error_code.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/buffer.hpp>

#include <spdlog/spdlog.h>

#include "dns_resolver.hpp"

#include <boost/asio.hpp>
#include <boost/beast.hpp>

namespace beast = boost::beast;			// from <boost/beast.hpp>
namespace http = beast::http;           // from <boost/beast/http.hpp>
using string_body = http::string_body;
using string_request = http::request<string_body>;
using request_parser = http::request_parser<string_request::body_type>;

class TcpSession final : public std::enable_shared_from_this<TcpSession> {
public:
    static std::shared_ptr<TcpSession> Create(boost::asio::io_context* context) {
        return std::shared_ptr<TcpSession>(new TcpSession(context));
    }

    ~TcpSession() {
        spdlog::trace("TcpSession {} destroy success.", reinterpret_cast<void*>(this));
        delete m_tcpSocket;
    };


    // Connect
    void asyncConnectToHost(std::string host, int port, std::function<void(const int&, const std::string&)> callback, DNSResolver::ResolveNetFamily netWorkFamily = DNSResolver::ResolveNetFamily::ForceIPV4) {
        m_host = host;
        m_port = port;
        // spdlog::trace("TcpSession {} async resolve host begin. Current pending callbacks: {}. Waiting delete: {}", reinterpret_cast<void*>(m_tcpSocket), m_pendingCallbacks, m_waitDelete);

        auto weak_self = weak_from_this();
        DNSResolver::getInstance()->asyncResolveHost(host, this, [weak_self, callback](const ResolveResult& result){
            if (auto self = weak_self.lock()){
                if (result.success) {
                    // spdlog::trace("TCPClient {} async resolve host success: {}. Current pending callbacks: {}. Waiting delete: {}", result.ip, reinterpret_cast<void*>(m_tcpSocket), m_pendingCallbacks, m_waitDelete);
                    
                    boost::system::error_code ec;
                    self->m_ip_address = boost::asio::ip::make_address(result.ip, ec);
                    if(!ec){
                        self->asyncConnectToHost(self->m_ip_address, self->m_port, callback);
                    }else{
                        callback(-1, "IP address DNS server returned convert failed.");
                    }
                }
                else {
                    // spdlog::trace("Resolve failed, err: {}", result.errMessage);
                    callback(-1, result.errMessage);
                }
            }
        }, netWorkFamily);
    }

    // Connect
    void asyncConnectToHost(boost::asio::ip::address addr, int port, std::function<void(const int&, const std::string&)> callback) {
        m_host = addr.to_string();
        m_ip_address = addr;
        m_port = port;

        auto weak_self = weak_from_this();
        m_tcpSocket->async_connect(boost::asio::ip::tcp::endpoint(addr, port), [weak_self, callback](const boost::system::error_code& ec) {
            if (auto self = weak_self.lock()){
                callback(ec.value(), ec.message());
            }
        });
    }


    // Write
    inline void asyncWriteData(const char* data, size_t size, std::function<void(const boost::system::error_code&, const size_t&)> callback) {
        auto weak_self = weak_from_this();
        boost::asio::async_write(*m_tcpSocket, boost::asio::buffer(data, size), [weak_self, callback](const boost::system::error_code& ec, size_t bytes_transferred) {
            if (auto self = weak_self.lock()){
                callback(ec, bytes_transferred);
            }
        });
    }


    // Read
    inline void asyncReadSomeData(char* buff, size_t size, std::function<void(const boost::system::error_code&, const size_t&)> callback) {
        auto weak_self = weak_from_this();
        m_tcpSocket->async_read_some(boost::asio::buffer(buff, size), [weak_self, callback](const boost::system::error_code& ec, size_t bytes_transferred) {
            if (auto self = weak_self.lock()){
                callback(ec, bytes_transferred);
            }
        });
    }



    // Async read http request
    inline void asyncReadHttpRequest(beast::flat_buffer& buffer, http::request<http::dynamic_body>& request, std::function<void(const boost::system::error_code&, const size_t&)> callback) {
        auto weak_self = weak_from_this();
        boost::beast::http::async_read(*m_tcpSocket, buffer, request, [weak_self, callback](const boost::system::error_code& ec, size_t bytes_transferred) {
            if (auto self = weak_self.lock()){
                callback(ec, bytes_transferred);
            }
        });
    }

    // Async write http data
    template<typename T>
    inline void asyncWriteHttpData(T& data, std::function<void(const boost::system::error_code&, const size_t&)> callback) {
        auto weak_self = weak_from_this();
        boost::beast::http::async_write(*m_tcpSocket, data, [weak_self, callback](const boost::system::error_code& ec, size_t bytes_transferred) {
            if (auto self = weak_self.lock()){
                callback(ec, bytes_transferred);
            }
        });
    }


    void cancelAsyncEvent() {
        try {
            m_tcpSocket->cancel();
            boost::system::error_code ec;
            m_tcpSocket->shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec); 
            m_tcpSocket->close(ec);
        } catch (const boost::system::system_error& e) {
        } catch (...) {
        }
    }

    std::string getRemoteAddressAndPort(){
        boost::asio::ip::tcp::endpoint remote_ep = m_tcpSocket->remote_endpoint();
        std::string remote_ip = remote_ep.address().to_string();
        unsigned short remote_port = remote_ep.port();
        return remote_ip + ":" + std::to_string(remote_port);
    }

    boost::asio::ip::tcp::socket* getTCPSocket(){
        return m_tcpSocket;
    }

    boost::asio::ip::address getPeerIPAddress(){
        return m_ip_address;
    }

    int getPeerPort(){
        return m_port;
    }

    boost::asio::io_context* getIOContext(){
        return m_io_context;
    }

private:
    TcpSession(boost::asio::io_context* context) {
        m_io_context = context;
        m_tcpSocket = new boost::asio::ip::tcp::socket(*context);
        spdlog::trace("TcpSession {} construct success.", reinterpret_cast<void*>(this));
    }
    boost::asio::io_context* m_io_context;

    std::string m_host;
    int m_port;
    boost::asio::ip::address m_ip_address;

    boost::asio::ip::tcp::socket* m_tcpSocket;
};

#endif