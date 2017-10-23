cmake_minimum_required(VERSION 3.8)
project(Files)

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES
        client.c
        server.c)

add_executable(Files ${SOURCE_FILES})