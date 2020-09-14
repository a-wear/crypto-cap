# security-scheme
This is a C implementation of the security-scheme.

## Table of Contents
- [Getting started](#getting-started)
    - [Dependencies](#dependencies)
- [Usage](#usage)
- [Build instructions](#build-instructions)
    - [Generic build options](#generic-build-options)
    - [JavaCard build options](#javacard-build-options)
    - [Android build options](#android-build-options)
- [Install dependencies](#install-dependencies)
    - [Install dependencies using the package manager](#install-dependencies-using-the-package-manager)
    - [Install dependencies from source](#install-dependencies-from-source)
- [Benchmarks](#benchmarks)
- [Project structure](#project-structure)
    - [Source tree](#source-tree)
    - [Source description](#source-description)
- [License](#license)

## Getting started
These instructions will get you a copy of the project up and running on your local machine for development
and testing purposes.

### Dependencies
The following table summarizes the tools and libraries required to build. By default,
the build uses the library installed on the system. However, if no library is found
installed on the system, you have to specify the path where the necessary libraries
are installed.

| Dependency   | Tested version  | Debian/Ubuntu pkg    | Optional | Purpose         |
| ------------ | --------------- | -------------------- | -------- | --------------- |
| CMake        | 3.18            | `cmake`              | NO       | -               |
| Zlib         | 1.2.11          | `zlib1g-dev`         | NO       | For OpenSSL     |
| OpenSSL      | 1.1.1g          | `libssl-dev`         | NO       | Cryptography    |
| PCSC         | 1.8.24          | `libpcsclite-dev`    | NO       | SmartCard PC/SC |
| PCSCD        | 1.8.24          | `pcscd`              | NO       | SmartCard PC/SC |

## Usage
1. Open a terminal within the folder with the executable
2. Start with `./security-scheme`

## Build instructions
x86-64/ARM/ARM64 Linux and macOS are supported. If you have any problems during compilation,
please check the [Install dependencies](#install-dependencies) section.

### Generic build options
- **Note**: this will produce the following executable: `security-scheme`

- `OPENSSL_ROOT_DIR` specify where the OpenSSL library is located
    - `cmake .. -DOPENSSL_ROOT_DIR=${openssl-dir}`
- `PCSC_ROOT_DIR` specify where the PCSC library is located
    - `cmake .. -DPCSC_ROOT_DIR=${pcsc-dir}`
- `CMAKE_BUILD_TYPE` set the build type
    - valid options: `Release` or `Debug`

### JavaCard build options
- **Note**: this will produce the additional executable: `security-scheme-javacard`

- `SECURITY_SCHEME_JAVACARD` allows to disable/enable the JavaCard support (default OFF)
    - `cmake .. -DSECURITY_SCHEME_JAVACARD=ON`

### Android build options
- **Note**: this will produce the additional executable: `security-scheme-android`

- `SECURITY_SCHEME_ANDROID` allows to disable/enable the Android support (default OFF)
    - `cmake .. -DSECURITY_SCHEME_ANDROID=ON`

## Install dependencies

### Install dependencies using the package manager
```sh
apt install cmake libssl-dev libpcsclite-dev pcscd
```

### Install dependencies from source

#### Compiling `zlib-1.2.11`
```sh
wget https://www.zlib.net/zlib-1.2.11.tar.gz
tar xzf zlib-1.2.11.tar.gz
cd zlib-1.2.11

./configure --prefix=/usr/local/zlib-1.2.11 --static
make -j 4
make install
```

#### Compiling `openssl-1.1.1g`
```sh
wget https://www.openssl.org/source/openssl-1.1.1g.tar.gz
tar xzf openssl-1.1.1g.tar.gz
cd openssl-1.1.1g

./Configure threads zlib \
            --with-zlib-include=/usr/local/zlib-1.2.11/include \
            --with-zlib-lib=/usr/local/zlib-1.2.11/lib \
            --prefix=/usr/local/openssl-1.1.1g \
            --openssldir=/usr/local/openssl-1.1.1g/etc \
            linux-generic32
make -j 4
make install
```

#### Compiling `cmake-3.18.0`
```sh
apt install libcurl4-openssl-dev libbz2-dev
```

```sh
wget https://github.com/Kitware/CMake/releases/download/v3.18.0/cmake-3.18.0.tar.gz
tar xzf cmake-3.18.0.tar.gz
mkdir cmake-3.18.0/build
cd cmake-3.18.0/build

../configure --prefix=/usr/local/cmake-3.18.0 --system-curl --parallel=4 -- \
              -DOPENSSL_ROOT_DIR=/usr/local/openssl-1.1.1g \
              -DZLIB_ROOT=/usr/local/zlib-1.2.11
make -j 4
make install
```

#### Compiling `pcsc-lite-1.9.0`
```sh
apt install libsystemd-dev libudev-dev
```

```sh
wget https://pcsclite.apdu.fr/files/pcsc-lite-1.9.0.tar.bz2
tar xjf pcsc-lite-1.9.0.tar.bz2
cd pcsc-lite-1.9.0

./configure --prefix=/usr/local/pcsc-lite-1.9.0
make -j 4
make install
```

#### Compiling `ccid-1.4.33`
```sh
apt install libusb-1.0-0-dev
```

```sh
wget https://ccid.apdu.fr/files/ccid-1.4.33.tar.bz2
tar xjf ccid-1.4.33.tar.bz2
cd ccid-1.4.33

export PKG_CONFIG_PATH=/usr/local/pcsc-lite-1.9.0/lib/pkgconfig

./configure --prefix=/usr/local/ccid-1.4.33
make -j 4
make install

# udev rules
cp src/92_pcscd_ccid.rules /etc/udev/rules.d/
```

#### *Note for Linux and Raspberry Pi OS users:*
You must create a file with the following content:

```sh
$ cat /etc/ld.so.conf.d/10-custom-libraries.conf
```

```sh
# openssl-1.1.1g
/usr/local/openssl-1.1.1g/lib
```

You must also patch the PCSC library using the following commands:

```sh
sed -i 's/#include <wintypes.h>/#include \"wintypes.h\"/g' /usr/include/PCSC/pcsclite.h
sed -i 's/#include <pcsclite.h>/#include \"pcsclite.h\"/g' /usr/include/PCSC/winscard.h
sed -i 's/#ifdef __APPLE__/#if !defined(WIN32)/g' /usr/include/PCSC/wintypes.h
```

To start the pcsc service you need to execute the following command:

```sh
/usr/local/pcsc-lite-1.9.0/sbin/pcscd --apdu --foreground --debug
```

## Benchmarks
The `benchmarking.sh` script can be used to automatically perform performance tests when the user works on
another platform.

It is possible to specify the number of iterations the script will perform and calculate the average more
accurately, as well as to configure the path of the executable and the directory where the results will be saved.

```sh
readonly ITERATIONS=25
readonly OUTPUT_DIR="benchmarks"
readonly EXECUTABLE="../build/security-scheme-javacard"
```

The script will generate two files:
- `<timestamp>_raw.txt`: all the times of each iteration
- `<timestamp>_csv.txt`: average time

Please, note that all times are expressed in seconds.

#### Structure of `<timestamp>_raw.txt`:

`total_computation_show_time;show_stage_1;show_stage_2;verification_time`

#### Structure of `<timestamp>_csv.txt`:

`total_computation_show_time;verification_time`

## Project structure

### Source tree

```sh
security-scheme
├── cmake
│   └── Modules
│       └── FindPCSC.cmake
├── CMakeLists.txt
├── config
│   └── config.h
├── include
│   ├── apdu.h
│   ├── models
│   │   ├── issuer.h
│   │   ├── user.h
│   │   └── verifier.h
│   └── system.h
├── lib
│   ├── apdu
│   │   ├── command.c
│   │   └── command.h
│   ├── helpers
│   │   ├── aes_helper.c
│   │   └── aes_helper.h
│   └── pcsc
│       ├── reader.c
│       └── reader.h
├── LICENSE.md
├── main.c
├── README.md
├── scripts
│   └── benchmarking.sh
└── src
    └── controllers
        ├── android
        │   ├── user.c
        │   └── user.h
        ├── issuer.c
        ├── issuer.h
        ├── javacard
        │   ├── user.c
        │   └── user.h
        ├── user.c
        ├── user.h
        ├── verifier.c
        └── verifier.h
```

### Source description

| Directory                    | File                           | Description                                                                                                             |
| ---------------------------- | ------------------------------ | ----------------------------------------------------------------------------------------------------------------------- |
|  `config/`                   |  `config.h`                    | constants (length of the nonce, length of the user id and verifier id, etc)                                             |
|  `include/`                  |  `apdu.h`                      | header with APDU codes used for communication with the smart cards                                                      |
|  `include/models/`           |  `*`                           | definition of the data structures (information) used by the issuer, the user and the verifier                           |
|  `include/`                  |  `system.h`                    | the system parameters used in aes operations (iv's and tag)                                                             |
|  `lib/apdu/`                 |  `command.{c,h}`               | functions defined to build and parse APDU packets                                                                       |
|  `lib/helpers/`              |  `aes_helper.{c,h}`            | function used to encrypt and decrypt using aes                                                                          |
|  `lib/pcsc/`                 |  `reader.{c,h}`                | functions defined for sending and receiving APDU packets, smart card communication                                      |
|  `scripts/`                  |  `benchmarking.sh`             | script used to automatically perform performance tests                                                                  |
|  `src/controllers/`          |  `issuer.{c,h}`                | code related to the operations performed by the issuer (signature of the user keys)                                     |
|  `src/controllers/android/`  |  `user.{c,h}`                  | code related to the operations performed by the user, Android (proof of key computation, information storage)           |
|  `src/controllers/javacard/` |  `user.{c,h}`                  | code related to the operations performed by the user, JavaCard (proof of key computation, information storage)          |
|  `src/controllers/`          |  `user.{c,h}`                  | code related to the operations performed by the user, PC (proof of key computation, information storage)                |
|  `src/controllers/`          |  `verifier.{c,h}`              | code related to the operations performed by the verifier (nonce generation, proof of key verification)                  |
|  `-`                         |  `main.c`                      | main routine                                                                                                            |
|  `-`                         |  `CMakeLists.txt`              | used for compiling code and building the application                                                                    |

## License
This project is licensed under the GPLv3 License - see the [LICENSE.md](LICENSE.md) file for details.
