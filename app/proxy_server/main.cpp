#include <boost/asio.hpp>
#include <spdlog/spdlog.h>

#include "../../proxy/proxy_server.h"

int main(int argc, char* argv[])
{
    spdlog::set_level(spdlog::level::info);
    spdlog::set_pattern("[%Y-%m-%d %H:%M:%S %^%l%$ thread:%t] %v");
    boost::asio::io_context context;
    ProxyServer proxyServer(context, 8000);
    context.run();
    return 0;
}
