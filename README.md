# Threshold ECDSA Signature

This project implements the threshold ECDSA protocol by [Canetti et al.](https://eprint.iacr.org/2021/060) that achieves non-interactive signing using 3 preprocessing rounds. 
It further provides malicious security and identifiable aborts.
We provide an implementation of the protocol in Kotlin using the secp256k1 elliptic curve.

The report on threshold ECDSA signatures for Atala PRISM and the project timeline can be found in the [Wiki](https://github.com/perun-network/atala-prism-threshold/wiki/Threshold-ECDSA-Signatures-for-Atala-PRISM-Report).

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Code Structure](#code-structure)
- [License](#license)

## Features

- Threshold ECDSA signing with preprocessing, where subsets of t signers can create signatures in one round.
- Implementation of the Paillier encryption scheme and Pedersen commitments.
- Zero-knowledge proofs for Paillier encryptions, which are during the signing process.
- The protocol can be integrated to [Apollo](https://github.com/hyperledger/identus-apollo) to be used in crypto services and the threshold Signature can be translated to Apollo's ECDSA Secp256k1 implementation.

## Architecture

The project is structured into several packages:

- **`ecdsa`**: Core ECDSA functionalities and mathematical operations.
- **`keygen`**: Key generation and precomputation.
- **`math`**: Mathematical operations and utilities used throughout the signing process.
- **`paillier`**: Implementation of the Paillier cryptosystem for encryption.
- **`pedersen`**: Pedersen commitment scheme with parameter generation.
- **`presign`**: Management of the presigning process, including rounds of communication and computations between signers.
- **`sign`**: Signing process management and partial signature combination.
- **`zero_knowledge`**: Zero-knowledge proof implementations.

## Requirements

- Kotlin 1.5 or higher
- Java Development Kit (JDK) 8 or higher
- Dependencies for cryptographic operations (included in the project)

## Installation

1. **Clone the Repository**:
    ```bash
       git clone https://github.com/yourusername/ecdsa-threshold-signing.git
    ```

2. **Navigate to the Project Directory**:
    ```bash
    cd ecdsa-threshold-signing
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

## Code Structure
- **`src`**: Contains all source code.
  - **`main`**: Contains main functionality.
    - **`ecdsa`**: Core functionalities.
    - **`keygen`**: Key generation and precomputation.
    - **`math`**: Mathematical operations and utilities.
    - **`paillier`**: Paillier cryptosystem implementation.
    - **`pedersen`**: Pedersen commitment management.
    - **`presign`**: Presigning process management.
    - **`sign`**: Signing process management.
    - **`zkproof`**: Zero-knowledge proof implementations.
    
  - **`test`**: Contains functionality test.
    - **`ecdsa`**: Contains unit test for the Secp256k1 ECDSA signatures. 
    - **`sign`**: Contains unit test for the signing of Threshold ECDSA.
    - **`zk`**: Contains unit test for zero-knowledge implementations.

## Limitations
The current implementation is currently lacking some intended features:

- Distributed key generation protocol by [Canetti et al.](https://eprint.iacr.org/2021/060) have not been fully implemented. (Currently centralized)
- Missing key refresh and adversary identification protocols.
- Main currently using precomputed secret primes to generate precomputations. This is to speed up the process. It is expected to have an accelerated prime generator incorporated in the precomputation phase. 

--- 
## Copyright
Copyright 2024 PolyCrypt GmbH. \
Use of the source code is governed by the Apache 2.0 license that can be found in the LICENSE file.
