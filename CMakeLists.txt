cmake_minimum_required(VERSION 3.14)
project(trdp_manager LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(trdp_manager
    src/main.cpp
    src/trdp_manager.cpp
    third_party/tinyxml2.cpp
)

target_include_directories(trdp_manager PRIVATE include third_party)

target_compile_definitions(trdp_manager PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT=0)

if(UNIX)
    find_package(Threads REQUIRED)
    target_link_libraries(trdp_manager PRIVATE Threads::Threads)
endif()

find_path(TRDP_INCLUDE_DIR trdp_if_light.h
    HINTS /usr/include /usr/local/include /opt/tcnopen/include /opt/trdp/include)
find_library(TRDP_LIBRARY NAMES trdp
    HINTS /usr/lib /usr/local/lib /opt/tcnopen/lib /opt/trdp/lib)

if(NOT TRDP_INCLUDE_DIR OR NOT TRDP_LIBRARY)
    message(FATAL_ERROR "TCNopen TRDP stack headers and libraries are required")
endif()

target_include_directories(trdp_manager PRIVATE ${TRDP_INCLUDE_DIR})
target_link_libraries(trdp_manager PRIVATE ${TRDP_LIBRARY})
