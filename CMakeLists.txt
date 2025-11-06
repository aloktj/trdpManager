cmake_minimum_required(VERSION 3.14)
project(trdp_manager LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(trdp_manager
    src/main.cpp
    src/trdp_manager.cpp
)

target_include_directories(trdp_manager PRIVATE include third_party)

target_compile_definitions(trdp_manager PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT=0)

if(UNIX)
    find_package(Threads REQUIRED)
    target_link_libraries(trdp_manager PRIVATE Threads::Threads)
endif()
