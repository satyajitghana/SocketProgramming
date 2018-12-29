cmake_minimum_required(VERSION 3.12)
project(SocketProgramming C)

set(CMAKE_C_STANDARD 99)

add_executable(SocketProgramming main.c packet_sniffer.c packet_sniffer.h)