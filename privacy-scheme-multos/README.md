# privacy-scheme-multos
This is a C implementation (user side) of the privacy-preserving scheme for MULTOS smart cards.

## Table of Contents
- [Getting started](#getting-started)
    - [Environment](#environment)
- [Build instructions](#build-instructions)
- [Install instructions](#install-instructions)
    - [How to know the Session Data Size](#how-to-know-the-session-data-size)
- [Benchmarks](#benchmarks)
    - [MULTOS-ML4](#multos-ml4)
- [Project structure](#project-structure)
    - [Source tree](#source-tree)
    - [Source description](#source-description)
- [License](#license)

## Getting started
These instructions will get you a copy of the project up and running on your local machine for development and
testing purposes.

Please, note that the process of compiling and building the application must be done on a **Windows** system.

### Environment
The following table summarizes the tools and libraries required to build and install the application.

| Dependency            | Description                                          | Purpose          |
| --------------------- | ---------------------------------------------------- | ---------------- |
| SmartDeck3_2Setup.msi | MULTOS SmartDeck 3.2.1                               | Smart card SDK   |
| vcredist_x86.exe      | Microsoft Visual C++ 2010  x86 Redistributable Setup | For MUtil        |
| vcredist_x64.exe      | Microsoft Visual C++ 2010  x64 Redistributable Setup | For MUtil        |
| MUtil.exe             | MUtil Application 2.8.0.5                            | App installation |

#### *Note for SmartDeck installation:*
- Specify the following installation path: `C:\SmartDeck`.
- Add `C:\SmartDeck\bin` to the system PATH.

## Build instructions
To compile the code and build the application (alu) it is necessary to execute the `make` command in the project's
root directory. This process will remove the old files and build the new application.

```sh
make
```

```console
C:\privacy-scheme-multos>make
rm -f main.hzo privacy-scheme-multos.hzx privacy-scheme-multos.alu
hcl -Iconfig -Iinclude -Ilib -c -g -o main.hzo main.c
hcl -g -o privacy-scheme-multos.hzx main.hzo
halugen privacy-scheme-multos.hzx
```

If you have any problems during compilation, please check the [Environment](#environment) section.

## Install instructions
- Insert a supported MULTOS smart card into the reader.
- Load the application to the smart card using the MUtil application with the following parameters:
    - **Filename**: `privacy-scheme-multos.alu`
    - **AID**: `F0000002`
    - **Session Data Size**: `0639 (Dec)`

### How to know the `Session Data Size`
In order to obtain the dynamic memory required by the application, it is necessary to execute the following command:

```sh
hls -t bin\\privacy-scheme-multos.hzx
```

```console
C:\privacy-scheme-multos>hls -t bin\\privacy-scheme-multos.hzx
   start     stop    size  decimal  name
00000000 0000027e     27f      639  .DB
00000000 000000ff     100      256  .PB
00000000 00000166     167      359  .SB
00000000 000001eb     1ec      492  .text
```

## Benchmarks

### MULTOS-ML4

| Total elapsed (sec)   | Computation (sec)     | Communication (sec)   | Verification (sec)    |
| --------------------- | --------------------- | --------------------- | --------------------- |
|  `0.541808`           |  `0.357448`           |  `0.184360`           |  `0.000528`           |

## Project structure

### Source tree

```sh
privacy-scheme-multos
├── CMakeLists.txt
├── config
│   └── config.h
├── include
│   ├── apdu.h
│   ├── models
│   │   ├── issuer.h
│   │   └── user.h
│   └── types.h
├── lib
│   ├── ecc
│   │   └── multosecc.h
│   └── helpers
│       ├── mem_helper.h
│       └── random_helper.h
├── LICENSE.md
├── main.c
├── Makefile
└── README.md
```

### Source description

| Directory                   | File                           | Description                                                                                                             |
| --------------------------- | ------------------------------ | ----------------------------------------------------------------------------------------------------------------------- |
|  `config/`                  |  `config.h`                    | constants (length of the nonce, length of the user id, etc)                                                             |
|  `include/`                 |  `apdu.h`                      | header with APDU codes used for communication with the smart card                                                       |
|  `include/models/`          |  `*`                           | definition of the data structures (information) used by the issuer and the user                                         |
|  `include/`                 |  `types.h`                     | custom defined data types used on the MULTOS platform                                                                   |
|  `lib/ecc/`                 |  `multosecc.h`                 | macros to perform mathematical operations on elliptic curves (MULTOS support)                                           |
|  `lib/helpers/`             |  `mem_helper.h`                | macros with custom implementation of memory operations (memcpy, memcmp, memzero)                                        |
|  `lib/helpers/`             |  `random_helper.h`             | macro for the generation of random numbers                                                                              |
|  `-`                        |  `main.c`                      | main routine                                                                                                            |
|  `-`                        |  `Makefile`                    | used for compiling code and building the application (alu)                                                              |

## License
This project is licensed under the GPLv3 License - see the [LICENSE.md](LICENSE.md) file for details.
