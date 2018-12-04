# NaCl.Core, a cryptography library for .NET

[![NuGet](https://img.shields.io/nuget/v/NaCl.Core.svg)](https://www.nuget.org/packages/NaCl.Core/)
[![Build Status](https://dev.azure.com/idaviddesmet/NaCl.Core/_apis/build/status/idaviddesmet.NaCl.Core)](https://dev.azure.com/idaviddesmet/NaCl.Core/_build/latest?definitionId=1)
[![Azure DevOps tests](https://img.shields.io/azure-devops/tests/idaviddesmet/NaCl.Core/1.svg?compact_message=)](https://dev.azure.com/idaviddesmet/NaCl.Core/_build/latest?definitionId=1)
[![Azure DevOps coverage](https://img.shields.io/azure-devops/coverage/idaviddesmet/NaCl.Core/1.svg)](https://dev.azure.com/idaviddesmet/NaCl.Core/_build/latest?definitionId=1)
[![License](https://img.shields.io/github/license/idaviddesmet/NaCl.Core.svg)](https://github.com/idaviddesmet/NaCl.Core/blob/master/LICENSE)
[![Maintenance](https://img.shields.io/maintenance/yes/2018.svg)](https://github.com/idaviddesmet/NaCl.Core)
[![contributions welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](https://github.com/idaviddesmet/NaCl.Core/issues)

## Introduction

**NaCl.Core** is a managed-only cryptography library for [.NET](https://dot.net) which provides modern cryptographic _primitives_.

Currently supported:

- **ChaCha20**, a high-speed stream cipher based on Salsa20.
- **XChaCha20**, based on ChaCha20 IETF with extended nonce (192-bit instead of 96-bit).
- **Poly1305**, a state-of-the-art secret-key message-authentication code (MAC).
- **ChaCha20-Poly1305**, an Authenticated Encryption with Associated Data (AEAD) algorithm; IETF variant as defined in [RFC8439](https://tools.ietf.org/html/rfc8439) and in its predecessor [RFC7539](https://tools.ietf.org/html/rfc7539).
- **XChaCha20-Poly1305**, a variant of ChaCha20-Poly1305 that utilizes the XChaCha20 construction in place of ChaCha20; as defined in the [RFC Draft](https://tools.ietf.org/html/draft-arciszewski-xchacha-02).

## Usage

### Symmetric Key Encryption

```csharp
// Create the primitive
var aead = new ChaCha20Poly1305(key);

// Use the primitive to encrypt a plaintext
var ciphertext = aead.Encrypt(plaintext, aad, nonce);

// ... or to decrypt a ciphertext
var output = aead.Decrypt(ciphertext, aad, nonce);
```

### MAC (Message Authentication Code)

```csharp
// Use the primitive to compute a tag
var tag = Poly1305.ComputeMac(key, data);

// ... or to verify a tag
Poly1305.VerifyMac(key, data, tag);
```

## Test Coverage

- Includes the mandatory RFC test vectors.
- [Project Wycheproof](https://github.com/google/wycheproof) by members of Google Security Team, for testing against known attacks (when applicable).

## Learn More

- [ChaCha, a variant of Salsa20](http://cr.yp.to/chacha/chacha-20080128.pdf) by Daniel J. Bernstein.
- [The Poly1305-AES message-authentication code](http://cr.yp.to/mac/poly1305-20050329.pdf) by Daniel J. Bernstein.
- [ChaCha20 and Poly1305 for IETF Protocols](https://tools.ietf.org/html/rfc8439) RFC.
- [XSalsa20](https://cr.yp.to/snuffle/xsalsa-20110204.pdf), an extended-nonce Salsa20 variant used in [NaCl](https://nacl.cr.yp.to).
- [XChaCha20-Poly1305](https://tools.ietf.org/html/draft-arciszewski-xchacha-02), an extended-nonce ChaCha20-Poly1305 IETF variant.
