#ifndef _HTTPCLIENT_
#define _HTTPCLIENT_

#include <boost/asio.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>

#include "dns_resolver.hpp"

#include <boost/beast/ssl.hpp>
#include <boost/asio/ssl.hpp>

#include "../utils/timer.hpp"


class HttpClient : public std::enable_shared_from_this<HttpClient> {
public:
    ~HttpClient(){
        spdlog::trace("HttpClient destroy success.");
    }

    static std::shared_ptr<HttpClient> Create(boost::asio::io_context* context) {
        return std::shared_ptr<HttpClient>(new HttpClient(context));
    }

    void setRequestMethod(boost::beast::http::verb method) {
        m_request.method(method);
    }

    void setRequestHost(std::string host) {
        m_request.set(boost::beast::http::field::host, host);
    }
    
    void setRequestTarget(std::string target) {
        m_request.target(target);
    }

    void setRequestPort(int port){
        m_port = port;
    }

    void setEnableSsl(bool enableSsl){
        m_enableSsl = enableSsl;
    }

    void setTimeOutSeconds(int seconds){
        m_timeOutSeconds = seconds;
    }

    void addRequestHeader(const std::string_view field, const std::string_view value) {
        m_request.set(field, value);
    }

    void addJsonData(const std::string& jsonString) {
        m_request.body() = jsonString;
        m_request.set(boost::beast::http::field::content_type, "application/json");
        m_request.prepare_payload();
    }

    void addFormData(const std::string_view key, const std::string_view value) {
        if (!m_request.body().empty()) {
            m_request.body() += "&";
        }
        m_request.body() += key;
        m_request.body() += "=";
        m_request.body() += value;

        m_request.set(boost::beast::http::field::content_type, "application/x-www-form-urlencoded");
        m_request.prepare_payload();
    }   
    

    void asyncSendHttpRequest(std::function<void(const bool&, const std::string&)> callback, DNSResolver::ResolveNetFamily netWorkFamily = DNSResolver::ResolveNetFamily::ForceIPV4) {
        m_callback = callback;
        std::string host = m_request[boost::beast::http::field::host];
        spdlog::trace("Post {}://{}:{}{}", m_enableSsl ? "https" : "http", host, m_port, m_request.target());

        if(m_enableSsl){
            m_sslContext = std::make_shared<boost::asio::ssl::context>(boost::asio::ssl::context::tlsv12_client);
            m_sslContext->set_verify_mode(boost::asio::ssl::verify_none);
            m_sslStream = std::make_shared<boost::beast::ssl_stream<boost::beast::tcp_stream>>(*m_context, (*m_sslContext));
            SSL_set_tlsext_host_name(m_sslStream->native_handle(), host.c_str());     // Set SNI Hostname 
        }else{
            m_tcpStream = std::make_shared<boost::beast::tcp_stream>(*m_context);
        }

        auto weak_self = weak_from_this();
        if(m_timeOutSeconds > 0){
            m_timer = Timer::Create(m_context);
            m_timer->asyncWait(m_timeOutSeconds, [weak_self](const boost::system::error_code& ec){
                if (auto self = weak_self.lock()) {
                    self->m_callback(false, "http timeout");
                }
            });
        }

        DNSResolver::getInstance()->asyncResolveHost(host, this, [weak_self](const ResolveResult& result){
            if (auto self = weak_self.lock()) {
                if (result.success) {
                    spdlog::trace("Resolve success: {}", result.ip);
                    boost::system::error_code ec;
                    boost::asio::ip::address ip_address = boost::asio::ip::make_address(result.ip, ec);
                    if(!ec){
                        self->asyncConnectToHost(boost::asio::ip::tcp::endpoint(ip_address, self->m_port));
                    }else{
                        self->m_callback(false, "host name resolution failed");
                    }
                }
                else {
                    spdlog::trace("Resolve failed, err: {}", result.errMessage);
                    self->m_callback(false, "host name resolution failed");
                }
            }
        }, netWorkFamily);
    }

    std::string getResponseBody(){
        return m_response.body();
    }

private:
    HttpClient(boost::asio::io_context* context){
        m_port = 80;
        m_enableSsl = false;
        m_context = context;
        m_timeOutSeconds = 0;
        spdlog::trace("HttpClient construct success.");
    }

    void asyncConnectToHost(boost::asio::ip::tcp::endpoint endpoint) {
        auto weak_self = weak_from_this();
        if(m_enableSsl){
            boost::beast::get_lowest_layer(*(m_sslStream)).async_connect(endpoint, [weak_self](const boost::system::error_code& ec){
                if (auto self = weak_self.lock()) {
                    if(!ec){
                        self->asyncSslHandShakeToHost();
                    }else{
                        spdlog::trace("Connect to host failed, error:{}", ec.message());
                        self->m_callback(false, "connect to host failed");
                    }
                }
            });
        }else{
            m_tcpStream->async_connect(endpoint, [weak_self](const boost::system::error_code& ec){
                if (auto self = weak_self.lock()) {
                    if(!ec){
                        self->asyncWriteRequestToHost();
                    }else{
                        spdlog::trace("Connect to host failed, error:{}", ec.message());
                        self->m_callback(false, "connect to host failed");
                    }
                }
            });
        }
    }

    void asyncSslHandShakeToHost(){
        auto weak_self = weak_from_this();
        m_sslStream->async_handshake(boost::asio::ssl::stream_base::client, [weak_self](const boost::system::error_code& ec){
            if (auto self = weak_self.lock()) {
                if(!ec){
                    self->asyncWriteRequestToHost();
                }else{
                    spdlog::trace("Connect to host failed, error:{}", ec.message());
                    self->m_callback(false, "connect to host failed");
                }
            }
        });
    }


    void asyncWriteRequestToHost(){
        if (m_enableSsl) {
            asyncWrite(*m_sslStream);
        } else {
            asyncWrite(*m_tcpStream);
        }
    }

    template<typename StreamType>
    void asyncWrite(StreamType& stream) {
        auto weak_self = weak_from_this();
        boost::beast::http::async_write(stream, m_request, [weak_self](const boost::system::error_code& ec, std::size_t bytes_transferred){
            if (auto self = weak_self.lock()) {
                if(!ec){
                    self->asyncReadResponseFromHost();
                }else{
                    spdlog::trace("Write request to host failed, error:{}", ec.message());
                    self->m_callback(false, "write request to host failed");
                }
            }
        });
    }

    void asyncReadResponseFromHost(){
        if (m_enableSsl) {
            asyncRead(*m_sslStream);
        } else {
            asyncRead(*m_tcpStream);
        }
    }

    template<typename StreamType>
    void asyncRead(StreamType& stream) {
        auto weak_self = weak_from_this();
        boost::beast::http::async_read(stream, m_response_buffer, m_response, [weak_self](const boost::system::error_code& ec, std::size_t bytes_transferred) {
            if (auto self = weak_self.lock()) {
                if(!ec){
                    if (200 == self->m_response.result_int()) {
                        spdlog::trace("Receive http response. OK");
                        self->m_callback(true, "success");
                    }
                    else {
                        int errCode = self->m_response.result_int();
                        int httpVersion = self->m_response.version();
                        int httpResult = static_cast<int>(self->m_response.result());
                        std::string reason(self->m_response.reason());
                        self->m_callback(false, "http error - " + std::to_string(errCode) + std::string("-") + std::to_string(httpResult) + "-" + reason);
                    }
                }else{
                    self->m_callback(false, "read response from host failed");
                }
            }
        });
    }

    void cancelAsyncEvent() {
        m_tcpStream->cancel();
        m_tcpStream->close();
    }

    int m_port;
    boost::asio::io_context* m_context;
    std::shared_ptr<boost::beast::tcp_stream> m_tcpStream;
    boost::beast::http::request<boost::beast::http::string_body> m_request;
    boost::beast::http::response<boost::beast::http::string_body> m_response;
    boost::beast::flat_buffer m_response_buffer;

    bool m_enableSsl;
    int m_timeOutSeconds;

    std::shared_ptr<Timer> m_timer;

    std::function<void(const bool&, const std::string&)> m_callback;

    std::shared_ptr<boost::asio::ssl::context> m_sslContext;
    std::shared_ptr<boost::beast::ssl_stream<boost::beast::tcp_stream>> m_sslStream;
};

#endif