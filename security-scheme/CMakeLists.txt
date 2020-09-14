cmake_minimum_required(VERSION 3.17)
project(security-scheme C)

set(CMAKE_C_STANDARD 90)

# SmartCard support options
option(SECURITY_SCHEME_JAVACARD "JavaCard version" OFF)
option(SECURITY_SCHEME_ANDROID "Android version" OFF)


# Custom CMake Modules path
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")

find_package(OpenSSL REQUIRED) # OpenSSL package

if (SECURITY_SCHEME_JAVACARD OR SECURITY_SCHEME_ANDROID)
  find_package(PCSC REQUIRED) # required to communicate with SmartCards
endif ()

# Project-level includes
include_directories(. ./include ./lib ./src)

set(EXECUTABLE_COMMON_SOURCE
  config/config.h
  include/models/issuer.h
  include/models/user.h
  include/models/verifier.h
  include/system.h
  lib/helpers/aes_helper.c
  lib/helpers/aes_helper.h
  src/controllers/issuer.c
  src/controllers/issuer.h
  src/controllers/verifier.c
  src/controllers/verifier.h
  main.c
)

# PC binary
add_executable(security-scheme ${EXECUTABLE_COMMON_SOURCE}
  src/controllers/user.c
  src/controllers/user.h
)
target_link_libraries(security-scheme PRIVATE OpenSSL::Crypto)
target_compile_definitions(security-scheme PRIVATE)


# JavaCard binary
if (SECURITY_SCHEME_JAVACARD)
  add_executable(security-scheme-javacard ${EXECUTABLE_COMMON_SOURCE}
    include/apdu.h
    lib/apdu/command.c
    lib/apdu/command.h
    lib/pcsc/reader.c
    lib/pcsc/reader.h
    src/controllers/javacard/user.c
    src/controllers/javacard/user.h
  )
  target_link_libraries(security-scheme-javacard PRIVATE OpenSSL::Crypto PCSC::PCSC)
  target_compile_definitions(security-scheme-javacard PRIVATE SECURITY_SCHEME_JAVACARD)
endif ()


# Android binary
if (SECURITY_SCHEME_ANDROID)
  add_executable(security-scheme-android ${EXECUTABLE_COMMON_SOURCE}
    include/apdu.h
    lib/apdu/command.c
    lib/apdu/command.h
    lib/pcsc/reader.c
    lib/pcsc/reader.h
    src/controllers/android/user.c
    src/controllers/android/user.h
  )
  target_link_libraries(security-scheme-android PRIVATE OpenSSL::Crypto PCSC::PCSC)
  target_compile_definitions(security-scheme-android PRIVATE SECURITY_SCHEME_ANDROID)
endif ()
