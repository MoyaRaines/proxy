add_definitions(-DUNICODE -D_UNICODE)

set(CMAKE_CXX_STANDARD 17)  
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)


# add_compile_options(-g -O0)  


MESSAGE(STATUS "C Compiler: ${CMAKE_C_COMPILER}")
MESSAGE(STATUS "CPP Compiler: ${CMAKE_CXX_COMPILER}")


### [Include File]
# Boost
include_directories("../../third_party/boost")
# Spdlog
include_directories("../../third_party/spdlog/include")


### [Compile Source]
list(APPEND COMMON_SOURCES "../../proxy/proxy_server.cpp") 



