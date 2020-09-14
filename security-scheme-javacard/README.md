# security-scheme-javacard
This is a Java implementation (user side) of the security-scheme for JavaCards.

## Table of Contents
- [Getting started](#getting-started)
    - [Environment](#environment)
- [Build instructions](#build-instructions)
- [Install instructions](#install-instructions)
- [Benchmarks](#benchmarks)
    - [NXP J3R200](#nxp-j3r200)
- [Project structure](#project-structure)
    - [Source tree](#source-tree)
    - [Source description](#source-description)
- [License](#license)

## Getting started
These instructions will get you a copy of the project up and running on your local machine for development and
testing purposes.

### Environment
The following table summarizes the tools and libraries required to build and install the application.

| Dependency            | Description                                     | Purpose               |
| --------------------- | ----------------------------------------------- | --------------------- |
| Java Card SDK         | Java Card Development Kit 3.0.5                 | Smart card SDK        |
| JDK 11                | Java SE Development Kit 11.0.7                  | -                     |
| Apache Ant            | Apache Ant 1.9.15                               | App build and install |

#### *Note for environment setup:*
- Add `/fake-path/jdk-11.0.7/bin` to the system PATH.
- Add `/fake-path/apache-ant-1.9.15/bin` to the system PATH.

```sh
export PATH=/fake-path/jdk-11.0.7/bin:${PATH}
export PATH=/fake-path/apache-ant-1.9.15/bin:${PATH}
```

## Build instructions
Before starting the compilation process it is necessary to make some changes in our environment.

- Create a copy of the example file `common.properties.example`.
```sh
cp common.properties.example common.properties
```

- Edit it and adjust the path of jc.home to the root directory of JavaCard's SDK.
```sh
vim common.properties

jc.home=/fake-path/java_card_kit-x_y_z/
```

To compile the code and build the application (cap) it is necessary to execute the `ant build` command in the project's
root directory. This process will remove the old files and build the new application.

```sh
ant build
```

```console
build:
      [cap] INFO: using JavaCard 3.0.5 SDK in /fake-path/java_card_kit-3_0_5/
      [cap] INFO: Setting package name to security_scheme
      [cap] Building CAP with 1 applet from package security_scheme (AID: 0102030405)
      [cap] security_scheme.Main 0102030405060708
  [compile] Compiling files from /fake-path/security-scheme-javacard/src
   [verify] Verification passed
      [cap] CAP saved to /fake-path/security-scheme-javacard/security-scheme-javacard.cap
      [exp] EXP saved to /fake-path/security-scheme-javacard/out/security-scheme/javacard/security-scheme.exp
      [jar] Building jar: /fake-path/security-scheme-javacard/out/security-scheme.jar
      [jar] JAR saved to /fake-path/security-scheme-javacard/out/security-scheme.jar
```

If you have any problems during compilation, please check the [Environment](#environment) section.

## Install instructions
- Insert a supported JavaCard into the reader.
- Load the application to the smart card using the following command: `ant install`.
    - A log file will be generated in `logs/<timestamp>_log.txt`.

## Benchmarks

### NXP J3R200

| Computation (sec)     | Verification (sec)    |
| --------------------- | --------------------- |
|  `0.627097`           |  `0.000036`           |

## Project structure

### Source tree

```sh
security-scheme-javacard
├── build.xml
├── common.properties.example
├── LICENSE.md
├── README.md
└── src
    └── security_scheme
        ├── Config.java
        ├── Main.java
        ├── UserController.java
        ├── UserModel.java
        ├── VerifierController.java
        └── VerifierModel.java
```

### Source description

| Directory                    | File                           | Description                                                                                                             |
| ---------------------------- | ------------------------------ | ----------------------------------------------------------------------------------------------------------------------- |
|  `src/security_scheme/`      |  `Config.java`                 | constants (length of the nonce, length of the user id and verifier id, etc)                                             |
|  `src/security_scheme/`      |  `Main.java`                   | main routine                                                                                                            |
|  `src/security_scheme/`      |  `UserController.java`         | code related to the operations performed by the user, JavaCard (proof of key computation, information storage)          |
|  `src/security_scheme/`      |  `UserModel.java`              | definition of the data structures (information) used by the user                                                        |
|  `src/security_scheme/`      |  `VerifierController.java`     | code related to the operations performed by the verifier (nonce generation, proof of key verification)                  |
|  `src/security_scheme/`      |  `VerifierModel.java`          | definition of the data structures (information) used by the verifier                                                    |
|  `-`                         |  `build.xml`                   | used for compiling code and building the application                                                                    |
|  `-`                         |  `common.properties.example`   | properties file used by the build.xml script                                                                            |

## License
This project is licensed under the GPLv3 License - see the [LICENSE.md](LICENSE.md) file for details.
