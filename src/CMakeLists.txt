cmake_minimum_required(VERSION 2.8)

project (libforte)
set(CMAKE_BUILD_TYPE Release)

set(forte_INCLUDE_DIRS
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/forte/
        ${CMAKE_SOURCE_DIR}/forte/string/
        ${CMAKE_SOURCE_DIR}/forte/crypto/
        ${CMAKE_SOURCE_DIR}/forte/crypto/primitives/
        ${CMAKE_SOURCE_DIR}/forte/crypto/primitives/encryption/
        ${CMAKE_SOURCE_DIR}/forte/crypto/primitives/encryption/internal/
    )

include_directories(
        ${forte_INCLUDE_DIRS}
        /usr/local/include/
        /usr/local/include/pbc/
    )

set(forte_SOURCES
        ${CMAKE_SOURCE_DIR}/forte/crypto/primitives/encryption/cbc_encrypter.c
        ${CMAKE_SOURCE_DIR}/forte/crypto/primitives/encryption/internal/cbc_bebgw.c
        ${CMAKE_SOURCE_DIR}/forte/crypto/primitives/encryption/internal/cbc_dummy.c
        ${CMAKE_SOURCE_DIR}/forte/crypto/primitives/encryption/internal/cbc_rsa.c
        ${CMAKE_SOURCE_DIR}/forte/string/forte_string.c
        forte/crypto/primitives/hashing/forte_Hasher.c forte/crypto/primitives/hashing/forte_Hasher.h forte/crypto/primitives/encryption/internal/forte_aes.c forte/crypto/primitives/encryption/internal/forte_aes.h)

link_directories(
    /usr/local/lib
    )

add_library(libforte SHARED ${forte_SOURCES})

# Link all of the required security libraries
target_link_libraries(libforte pbc crypto ssl gmp)
