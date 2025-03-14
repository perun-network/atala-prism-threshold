# Threshold ECDSA Signature

[![Test Coverage](https://github.com/perun-network/atala-prism-threshold/blob/gh-pages/badges/jacoco.svg?raw=true)](https://perun-network.github.io/atala-prism-threshold/)
[![CI](https://github.com/perun-network/atala-prism-threshold/actions/workflows/ci_cd.yml/badge.svg)](https://github.com/perun-network/atala-prism-threshold/actions/workflows/ci_cd.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

This project implements the threshold ECDSA protocol by [Canetti et al.](https://eprint.iacr.org/2021/060) (2021) that achieves non-interactive signing using 3 preprocessing rounds. 
It further provides malicious security and identifiable aborts.

We provide an implementation of the protocol in Kotlin using the secp256k1 elliptic curve.

The report on threshold ECDSA signatures for Atala PRISM and the project timeline can be found in the [Wiki](https://github.com/perun-network/atala-prism-threshold/wiki/Threshold-ECDSA-Signatures-for-Atala-PRISM-Report).

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Test](#test)
- [Code Structure](#code-structure)
- [Limitations](#limitations)
- [Copyright](#copyright)

## Features

- Threshold ECDSA signing with preprocessing, where subsets of t signers can create signatures in one round.
- Implementation of the Paillier encryption scheme and Pedersen commitments.
- Zero-knowledge proofs to prove the validity of computations along the execution of the protocol.
- The protocol can be integrated to [Apollo](https://github.com/hyperledger/identus-apollo) to be used in crypto services and the threshold Signature can be translated to Apollo's ECDSA Secp256k1 implementation.

## Architecture

The project is structured into several packages:

- **`ecdsa`**: Core ECDSA functionalities and mathematical operations.
- **`precomp`**: Centralized key generation and precomputation.
- **`math`**: Mathematical operations and utilities used throughout the signing process.
- **`paillier`**: Implementation of the Paillier cryptosystem for encryption.
- **`pedersen`**: Pedersen commitment scheme with parameter generation.
- **`sign`**: Signing process management and partial signature combination.
  - **`keygen`**: 3-round Key generation protocol.
  - **`aux`**: 3-round key refresh/auxiliary-info protocol.
  - **`presign`**: 3-round presigning protocol.
- **`zero_knowledge`**: Zero-knowledge proof implementations.

## Requirements

- Kotlin 2.0 or higher
- Java Development Kit (JDK) 11 or higher
- Dependencies for cryptographic operations (included in the project)

## Installation

1. **Clone the Repository**:
    ```bash
       git clone https://github.com/perun-network/atala-prism-threshold.git
    ```

2. **Navigate to the Project Directory**:
    ```bash
    cd atala-prism-threshold
    ```

3. **Build the Project**:
    ```bash
    ./gradlew build
    ```

4. **Run the Application**:
    ```bash
    ./gradlew run
    ```

## Usage
The main entry point for the threshold signing process is located in the `main` function of the `perun_network.ecdsa_threshold` package.

- Modify the `message` variable to sign different messages.
- Adjust the number of signers (`n`) and the threshold (`t`) as needed.

The application will output the execution time and confirm if the ECDSA signature was generated and verified successfully.

### Usage in another project

You can integrate this library into other Kotlin-based projects by adding the following to your `build.gradle.kts` using JitPack:

```kotlin
repositories {
    maven { url = uri("https://jitpack.io") }
}

dependencies {
    implementation("com.github.perun-network:atala-prism-threshold:v0.1.3")
}
```

### Example: Using Threshold ECDSA Signing in Another Project

```kotlin
import perun_network.ecdsa_threshold.sign.Signer

class BackendSigner (
    val name: String,
    val thresholdSigner : Signer,
)
```


## Test
This section describes the testing strategy and tools used to maintain code quality and reliability.

### Testing Frameworks and Tools
- **Framework**: The project uses [JUnit 5](https://junit.org/junit5/) for unit and integration testing.
- **Build Tool Integration**: Tests are executed using Gradle's test task.

### Unit Tests and Integration Tests.
    - Test individual components (e.g., classes, functions) in isolation.
    - Validate interactions between components.
    - Located in `src/test/kotlin`.

### Running Tests
To execute tests locally:

- **Run all tests**:
    ```bash
    ./gradlew test
    ```
- **Run a specific test class:
    ```bash
    ./gradlew test --tests <class_name>
    ```
### Test Coverage Report
The project uses [JaCoCo](https://www.eclemma.org/jacoco/) to measure test coverage.

1. Generate Coverage Report: Run the following command to generate the coverage report:
    ```bash
    ./gradlew jacocoTestReport
    ```
2. View the Report: The HTML report is available at:
    ```bash
    build/reports/jacoco/test/html/index.html
    ```
   or online at 
[Test Report](https://perun-network.github.io/ecdsa-threshold/)

3. Coverage Standards:
   - Instruction coverage: 90% or higher.
   - Branches coverage: 80% or higher
   - Critical areas must be thoroughly covered.

## Code Structure
- **`src`**: Contains all source code.
  - **`main`**: Contains main functionality.
    - **`ecdsa`**: Core functionalities.
    - **`precomp`**: Centralized key generation and precomputation.
    - **`math`**: Mathematical operations and utilities.
    - **`paillier`**: Paillier cryptosystem implementation.
    - **`pedersen`**: Pedersen commitment management.
    - **`sign`**: Signing process management.
      - **`keygen`**: Keygen process management.
      - **`aux`**: Aux-Info process management.
      - **`presign`**: Presigning process management. 
    - **`zero_knowledge`**: Zero-knowledge proof implementations.
    
  - **`test`**: Contains functionality test.
    - **`ecdsa`**: Contains unit test for the Secp256k1 ECDSA signatures. 
    - **`math`**: Contains unit test for the `math` classes.
    - **`paillier`**: Contains unit test for the Paillier encryption scheme.
    - **`precomp`**: Contains unit test for the `precomputation` classes.
    - **`sign`**: Contains unit test for the signing of Threshold ECDSA.
    - **`zk`**: Contains unit test for zero-knowledge implementations.

## Limitations
The current implementation is currently lacking some intended features:

- Main currently using precomputed secret primes to generate precomputations. This is to speed up the process. It is expected to have an accelerated prime generator incorporated in the precomputation phase. 
- Parallelization of Broadcast communication.

---
## Copyright
Copyright 2024 PolyCrypt GmbH. \

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Use of the source code is governed by the Apache 2.0 license that can be found in the [LICENSE](LICENSE) file.
