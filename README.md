# 基于Boost库实现的Socks4/Socks5/Http代理

## 项目简介

该项目基于Boost库，使用智能指针实现了异步安全，具有高性能且支持标准`socks4/socks4a/socks5/http`协议的`proxy server`。`proxy server`可以同时接收`socks`或`http`代理请求，服务端能根据请求协议的前几个字节自动甄别协议的类型，从而实现支持不同协议运行在同一服务端口。

## TODO

- proxy client客户端功能开发
- Socks5协议UDP功能支持
- SSL协议支持
- Ban客户端IP（IP地理数据库识别ban指定地区、IP）
- ProxyServer多级中继
- 随机噪声干扰功能
- happyeyeballs连接算法
- 限速功能
- 账密认证配置方式

## 项目依赖

- Boost
- Spdlog

## 项目框架

- app：应用
- net：TCP/HTTP/DNS
- pool: 池化
- proxy：Socks4/Socks5/Http代理
- utils: 工具集

## 编译构建

### 1. 拉取此仓库

```bash
git clone <source url>
```

### 2. 拉取第三方子模块

```bash
git submodule update --init --recursive
```

### 3. 切换boost库至指定版本后重新拉取更新，并生成boost库头文件

```bash
cd third_party/boost
git checkout boost-1.87.0
git submodule update --init --recursive

./bootstrap.sh
./b2 headers
```

### 4. 进入构建目录并新建一个文件夹

```bash
cd build
mkdir proxy_server
cd proxy_server
```

### 5. 使用CMakeLists生成CMake文件

``` bash
Unix           cmake ../../app/proxy_server
Windows 32bits  cmake -G "Visual Studio 16 2019" -A Win32 ..\..\app\proxy_server
Windows 64bits  cmake -G "Visual Studio 16 2019" -A x64 ..\..\app\proxy_server
```

### 6. 编译

``` bash
Unix   make -j
Windows cmake --build . --config Release
```

## 使用示例

``` bash
./proxy_server
[2025-06-16 21:08:11 info thread:31280] ProxyServer localhost:8000 start accept client connection.
[2025-06-16 21:08:11 info thread:31280] Number of cpu cores: 8
[2025-06-16 21:08:11 info thread:31280] IO context thread pool construct success. Pool size: 12


curl -x http://127.0.0.1:8000 ipinfo.io
curl -x socks5://127.0.0.1:8000 ipinfo.io
curl -x socks4://127.0.0.1:8000 ipinfo.io

[2025-06-16 21:08:26 info thread:2564] Proxy server: http GET ipinfo.io (127.0.0.1:27571 <--> 34.117.59.81:80)  660 bytes / 0 s.
[2025-06-16 21:08:28 info thread:33968] Proxy server socks4 34.117.59.81 (127.0.0.1:27574 <--> 34.117.59.81:80)  732 bytes / 0 s.
[2025-06-16 21:08:29 info thread:15444] Proxy server: socks5 34.117.59.81 (127.0.0.1:27578 <--> 34.117.59.81:80)  732 bytes / 0 s.
```