# CMakeLists.txt
cmake_minimum_required (VERSION 3.12)
include("../common.cmake")

set(_PROJECT_NAME_ "proxy_server")
project (${_PROJECT_NAME_})

list(APPEND COMMON_SOURCES "main.cpp") 
add_executable (${_PROJECT_NAME_} ${COMMON_SOURCES})

set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")

