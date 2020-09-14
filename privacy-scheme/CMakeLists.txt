cmake_minimum_required(VERSION 3.17)
project(privacy-scheme C)

set(CMAKE_C_STANDARD 90)

# SmartCard support options
option(PRIVACY_SCHEME_MULTOS "MultOS version" OFF)
option(PRIVACY_SCHEME_ANDROID "Android version" OFF)


# Custom CMake Modules path
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")

find_package(OpenSSL REQUIRED) # OpenSSL package
find_package(MCL REQUIRED) # MCL package

if (PRIVACY_SCHEME_MULTOS OR PRIVACY_SCHEME_ANDROID)
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
  include/types.h
  lib/helpers/epoch_helper.c
  lib/helpers/epoch_helper.h
  lib/helpers/hash_helper.c
  lib/helpers/hash_helper.h
  lib/helpers/hex_helper.c
  lib/helpers/hex_helper.h
  lib/helpers/mcl_helper.c
  lib/helpers/mcl_helper.h
  src/controllers/issuer.c
  src/controllers/issuer.h
  src/controllers/verifier.c
  src/controllers/verifier.h
  src/setup.c
  src/setup.h
  main.c
)

# PC binary
add_executable(privacy-scheme ${EXECUTABLE_COMMON_SOURCE}
  src/controllers/user.c
  src/controllers/user.h
)
target_link_libraries(privacy-scheme PRIVATE MCL::Bn256 OpenSSL::Crypto)
target_compile_definitions(privacy-scheme PRIVATE)


# MULTOS binary
if (PRIVACY_SCHEME_MULTOS)
  add_executable(privacy-scheme-multos ${EXECUTABLE_COMMON_SOURCE}
    include/apdu.h
    lib/apdu/command.c
    lib/apdu/command.h
    lib/helpers/smartcard_helper.c
    lib/helpers/smartcard_helper.h
    lib/pcsc/reader.c
    lib/pcsc/reader.h
    src/controllers/multos/user.c
    src/controllers/multos/user.h
  )
  target_link_libraries(privacy-scheme-multos PRIVATE MCL::Bn256 OpenSSL::Crypto PCSC::PCSC)
  target_compile_definitions(privacy-scheme-multos PRIVATE PRIVACY_SCHEME_MULTOS)
endif ()


# Android binary
if (PRIVACY_SCHEME_ANDROID)
  add_executable(privacy-scheme-android ${EXECUTABLE_COMMON_SOURCE}
    include/apdu.h
    lib/apdu/command.c
    lib/apdu/command.h
    lib/helpers/smartcard_helper.c
    lib/helpers/smartcard_helper.h
    lib/pcsc/reader.c
    lib/pcsc/reader.h
    src/controllers/android/user.c
    src/controllers/android/user.h
  )
  target_link_libraries(privacy-scheme-android PRIVATE MCL::Bn256 OpenSSL::Crypto PCSC::PCSC)
  target_compile_definitions(privacy-scheme-android PRIVATE PRIVACY_SCHEME_ANDROID)
endif ()
