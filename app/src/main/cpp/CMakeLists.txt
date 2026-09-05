cmake_minimum_required(VERSION 3.22.1)
project("nk_native_checks")

add_library(nk_native_checks SHARED
        nk_native_checks.cpp)

find_library(log-lib log)

target_link_libraries(nk_native_checks
        ${log-lib})
