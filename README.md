# zkTLS: Zero-Knowledge Transport Layer Security

## Overview

zkTLS is a proof-of-concept implementation of a Transport Layer Security (TLS) protocol with zero-knowledge elements. It combines traditional TLS handshake procedures with Multi-Party Computation (MPC) and Garbled Circuits to enhance privacy and security.

## Features

- TLS-like handshake protocol
- Garbled Circuit implementation for secure computation
- Oblivious Transfer (OT) protocol
- Multi-Party Computation (MPC) for key derivation
- Secure communication using AES-GCM encryption

## Project Structure

- `garbled_circuit.py`: Implementation of the Garbled Circuit
- `oblivious_transfer.py`: Implementation of the Oblivious Transfer protocol
- `mpc_party.py`: Multi-Party Computation party and handshake
- `tls_handshake.py`: TLS handshake implementation
- `secure_communication.py`: Secure communication using derived keys
- `main.py`: Entry point for running the client or server

## Requirements

- Python 3.7+
- cryptography library

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/zkTLS.git
   cd zkTLS
   ```

2. Install the required dependencies:
   ```
   pip install cryptography
   ```

## Usage

To run the server:

```
python main.py server
```

To run the client:

```
python main.py client
```


## Security Considerations

This is a proof-of-concept implementation and should not be used in production environments. It lacks many security features of a full TLS implementation, including:

- Complete certificate chain validation
- Support for multiple cipher suites
- Session resumption
- Perfect forward secrecy
- Protection against various attacks (e.g., padding oracle, timing attacks)

## Contributing

Contributions to improve the implementation or add features are welcome. Please submit a pull request or open an issue to discuss proposed changes.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This implementation is for educational purposes only and should not be used in production systems or to protect sensitive information.