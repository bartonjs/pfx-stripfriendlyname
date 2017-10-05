
project(stripfriendlyname)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
cmake_minimum_required(VERSION 3.5)

add_compile_options(-Wno-cast-align)
add_definitions(-DPIC=1)

find_package(OpenSSL REQUIRED)
include_directories(SYSTEM ${OPENSSL_INCLUDE_DIR})

set(SOURCES
    stripfriendlyname.c
)

add_executable(stripfriendlyname
    ${SOURCES}
)

target_link_libraries(stripfriendlyname
    ${OPENSSL_CRYPTO_LIBRARY}
)
