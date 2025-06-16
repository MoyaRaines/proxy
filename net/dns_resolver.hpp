#pragma once
#ifndef DNSRESOLVER_H
#define DNSRESOLVER_H

#include <iostream>
#include <list>
#include <vector>
#include <string>
#include <functional>  
#include <memory>
#include <time.h>
#include <map>

#include <boost/asio.hpp>
#include <boost/system/error_code.hpp>

#include "../pool/io_context_thread_pool.hpp"

#if defined(_USE_CARES_RESOLVE_DOMAIN_)
#include <ares.h>
#endif


struct ResolveResult{
    bool success;
    std::string ip;
    std::string errMessage;
};

struct CallBackItem {
    void* obj_ptr;
    std::function<void(const ResolveResult&)> callback;
};


class DNSResolver{
public:
    static DNSResolver* getInstance(){
        static DNSResolver* instance = NULL;
        if (NULL == instance){
            instance = new DNSResolver();
        }
        return instance;
    }

    enum ResolveNetFamily {
        ForceIPV6,
        PreferredIPV6,
        ForceIPV4
    };

    DNSResolver() {
        m_resolver = new boost::asio::ip::tcp::resolver(*IOContextThreadPool::getInstance()->get_io_context());

    #if defined(_USE_CARES_RESOLVE_DOMAIN_)
        int status = ares_library_init(ARES_LIB_INIT_ALL);
        if (status != ARES_SUCCESS) {
            spdlog::error("c-ares dns library init failed!");
            std::exit(-1);
        }

    
        spdlog::trace("DNSResolver construct success.");
    #endif 
    }

    #if defined(_USE_CARES_RESOLVE_DOMAIN_)
    void initAres() {
        struct ares_options options;
        options.timeout = 4 * 1000;                // 设置超时时间，mask：ARES_OPT_TIMEOUT
        options.tries = 1;
        options.evsys = ARES_EVSYS_DEFAULT;
        int optmask = ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES | ARES_OPT_EVENT_THREAD;

        if(m_ares_dns_network_protocol == "tcp"){
            options.flags = ARES_FLAG_USEVC;    // 使用 TCP，mask：ARES_OPT_FLAGS
            optmask = optmask | ARES_OPT_FLAGS;
        }
        

        int status = ares_init_options(&m_ares_channel, &options, optmask);
        if (status != ARES_SUCCESS) {
            printf("ares_init_options: %s\n", ares_strerror(status));
            std::exit(-1);
        }
        if(!m_use_default_dns_server){
            int status = ares_set_servers_csv(m_ares_channel, m_ares_dns_server.c_str());
            if (status != ARES_SUCCESS) {
                // return false;
            }
        }

        m_ares_dns_server = getAresDNSServers();
    }
    #endif

    // 发起异步域名解析
    void asyncResolveHost(std::string host, void* objPtr, std::function<void(const ResolveResult)> callback, ResolveNetFamily resolveNetFamliy = ForceIPV4){
        spdlog::trace("asyncResolveHost: {}", host);
        boost::system::error_code ec;
        boost::asio::ip::address ipAddress = boost::asio::ip::make_address(host, ec);
        if (!ec) {  // IP地址 -- 直接回调
            callback(ResolveResult{ true, host, "success"});
        } else {    // 域名 -- 进行解析
            m_hostMapMutex.lock();
            auto it = m_hostMap.find(host);
            if (it != m_hostMap.end()) {    // 存在相同的解析请求，进行合并
                it->second.emplace_back(CallBackItem{ objPtr, callback });
                 m_hostMapMutex.unlock();
            }
            else {  // 不存在相同的解析请求，新创建
                m_hostMap[host] = { CallBackItem{objPtr, callback} };
                 m_hostMapMutex.unlock();
                #if defined(_USE_CARES_RESOLVE_DOMAIN_)
                    asyncResolveByCAres(host, resolveNetFamliy);
                #else
                    asyncResolveByBoost(host, resolveNetFamliy);
                #endif
            }
        }
    }

    void asyncResolveByBoost(std::string host, ResolveNetFamily resolveNetFamliy) {
        m_resolver->async_resolve(host, "", [this, host, resolveNetFamliy](const boost::system::error_code& ec, boost::asio::ip::tcp::resolver::results_type boost_results){
            ResolveResult result = { false, "", "" };
            if (!ec) {
                boost::asio::ip::tcp::endpoint endpoints;

                if(resolveNetFamliy == DNSResolver::ForceIPV6){
                    endpoints = this->getFirstIPv6Endpoint(boost_results);
                    if(endpoints.address().is_v6()){
                        result.success = true;
                        result.ip = endpoints.address().to_string();
                    }else{
                        result.success = false;
                        result.errMessage = "dns no ipv6 returned";
                    }
                }else if(resolveNetFamliy == DNSResolver::PreferredIPV6){
                    endpoints = this->getFirstIPv6Endpoint(boost_results);
                    if(endpoints.address().is_v6()){
                        result.success = true;
                        result.ip = endpoints.address().to_string();
                    }else{
                        endpoints = this->getFirstIPv4Endpoint(boost_results);
                        if(endpoints.address().is_v4()){
                            result.success = true;
                            result.ip = endpoints.address().to_string();
                        }else{
                            result.success = false;
                            result.errMessage = "dns no ip returned";
                        }
                    }
                }else{
                    endpoints = this->getFirstIPv4Endpoint(boost_results);
                    if(endpoints.address().is_v4()){
                        result.success = true;
                        result.ip = endpoints.address().to_string();
                    }else{
                        result.success = false;
                        result.errMessage = "dns no ipv4 returned";
                    }
                }
            }
            else {
                result.success = false;
                result.errMessage = ec.message();
            }
            callBackTransferCore(host, result);
        });
    }


    #if defined(_USE_CARES_RESOLVE_DOMAIN_)
    bool setAresDnsServer(std::string dns_server){
        boost::system::error_code ec;
        boost::asio::ip::address ipAddress = boost::asio::ip::make_address(dns_server, ec);
        if (ec) {
            return false;
        }else{
            m_ares_dns_server = dns_server;
            m_use_default_dns_server = false;
            return true;
        }
    }
    #endif

    bool setAresDnsNetWorkProtocol(std::string networkProtocol){
        if(networkProtocol == "tcp" || networkProtocol == "udp"){
            m_ares_dns_network_protocol = networkProtocol;
            return true;
        }else{
            return false;
        }
    }
    std::string getAresDnsNetWorkProtocol(){
        return m_ares_dns_network_protocol;
    }

    bool getUseDefaultDnsServer(){
        return m_use_default_dns_server;
    }


#if defined(_USE_CARES_RESOLVE_DOMAIN_)
    std::string getAresDNSServers() {
        char* servers_csv = ares_get_servers_csv(m_ares_channel);
        if (!servers_csv) {
            return "";
        }
        std::string csv(servers_csv);
        ares_free_string(servers_csv); 
        return csv;
    }

    void asyncResolveByCAres(std::string host, ResolveNetFamily resolveNetFamliy) {
        struct ares_addrinfo_hints hints;
        if(resolveNetFamliy == ResolveNetFamily::PreferredIPV6){
            hints.ai_family = AF_UNSPEC;        // AF_UNSPEC - Any
        }else if(resolveNetFamliy == ResolveNetFamily::ForceIPV6){
            hints.ai_family = AF_INET6;         // AF_INET6 - IPV6   
        }else{
            hints.ai_family = AF_INET;          // AF_INET - IPV4    
        }
        
        // 适用于TCP/UDP的地址
        // SOCK_STREAM - TCP    SOCK_DGRAM - UDP    0 - Any
        hints.ai_socktype = SOCK_STREAM; 
        
        std::string* hostCopy = new std::string(host);
        void* ptr = static_cast<void*>(hostCopy);
        ares_getaddrinfo(m_ares_channel, host.c_str(), "0", &hints, &DNSResolver::callBackTransferByCAres, ptr);
    }
#endif


    // 取消异步域名解析    
    void cancelAsyncResolveHost(std::string host, void* objPtr){
        auto it = m_hostMap.find(host);
        if (it != m_hostMap.end()) {
            auto& callbackItems = it->second;

            // 只有单个回调正在等待返回，直接删掉
            if (callbackItems.size() == 1) {
                m_hostMap.erase(it);
            } else {    // 有多个回调正在等待返回，根据回调对象的指针进行删除
                callbackItems.erase(std::remove_if(callbackItems.begin(), callbackItems.end(),
                    [&objPtr](const CallBackItem& item) {
                        return item.obj_ptr == objPtr;
                    }),
                    callbackItems.end());
            }
        } else {

        }
    }


    void callBackTransferCore(std::string host, ResolveResult& result) {
        m_hostMapMutex.lock();
        auto it_callback = m_hostMap.find(host);
        if (it_callback != m_hostMap.end()) {       // 该域名存在回调
            auto& requests = it_callback->second;
            m_hostMapMutex.unlock();
            spdlog::trace("Resolve callBackTransfer: {} - {}  Callback amounts: {} ", host, result.ip, requests.size());
            for (auto& request : requests) {
                request.callback(result);
            }
            m_hostMapMutex.lock();
            m_hostMap.erase(it_callback);
            m_hostMapMutex.unlock();
        }
        else {
            spdlog::trace("No resolve requests found for host: {}", host);
            m_hostMapMutex.unlock();
        }
        
    }

#if defined(_USE_CARES_RESOLVE_DOMAIN_)
    static void callBackTransferByCAres(void* ptr, int status, int timeouts, struct ares_addrinfo* result) {
        std::string* hostPtr = reinterpret_cast<std::string*>(ptr);
        spdlog::trace("Cares resolve callback {}", *hostPtr);

        ResolveResult resolveResult = { false, "", "" };
        if (status == ARES_SUCCESS) {
            struct ares_addrinfo* addr = result;
            struct ares_addrinfo_node* addr_node = result->nodes;
            
            std::string ip;
            if (addr_node->ai_family == AF_INET) {
                char ip_cchar[INET_ADDRSTRLEN];
                struct sockaddr_in* ipv4 = (struct sockaddr_in*)addr_node->ai_addr;
                inet_ntop(AF_INET, &(ipv4->sin_addr), ip_cchar, INET_ADDRSTRLEN);
                ip = ip_cchar;
            }
            else if (addr_node->ai_family == AF_INET6) {
                char ip_cchar[INET6_ADDRSTRLEN];
                struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)addr_node->ai_addr;
                inet_ntop(AF_INET6, &(ipv6->sin6_addr), ip_cchar, INET6_ADDRSTRLEN);
                ip = ip_cchar;
            }
            resolveResult.success = true;
            resolveResult.ip = ip;
        }
        else {
            resolveResult.success = false;
            resolveResult.errMessage = ares_strerror(status);
            spdlog::trace("Resolve host by c-ares failed, error: {}", ares_strerror(status));
        }   
        DNSResolver::getInstance()->callBackTransferCore(*hostPtr, resolveResult);
        delete hostPtr;
    }
#endif


private:
    boost::asio::ip::tcp::endpoint getFirstIPv4Endpoint(const boost::asio::ip::tcp::resolver::results_type& endpoints) {
        auto it = std::find_if(endpoints.begin(), endpoints.end(),
            [](const boost::asio::ip::tcp::resolver::endpoint_type& endpoint) {
                return endpoint.address().is_v4();
            });
        
        return (it != endpoints.end()) ? *it : boost::asio::ip::tcp::endpoint();
    }

    boost::asio::ip::tcp::endpoint getFirstIPv6Endpoint(const boost::asio::ip::tcp::resolver::results_type& endpoints) {
        auto it = std::find_if(endpoints.begin(), endpoints.end(),
            [](const boost::asio::ip::tcp::resolver::endpoint_type& endpoint) {
                return endpoint.address().is_v6();
            });
        
        return (it != endpoints.end()) ? *it : boost::asio::ip::tcp::endpoint();
    }

private:
    static DNSResolver* instance;

    std::map<std::string, std::list<CallBackItem>> m_hostMap;
    std::string m_ares_dns_server = "";
    std::string m_ares_dns_network_protocol = "udp";
    bool m_use_default_dns_server = true;

    std::mutex m_hostMapMutex; 

    boost::asio::ip::tcp::resolver* m_resolver;

    #if defined(_USE_CARES_RESOLVE_DOMAIN_)
    ares_channel m_ares_channel;
    #endif
};

#endif