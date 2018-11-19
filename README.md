# NaCl.Core, a cryptography library for .NET

[![Build status](https://ci.appveyor.com/api/projects/status/2k3cxt2e1r2jyinx?svg=true)](https://ci.appveyor.com/project/idaviddesmet/nacl-core)
[![Build Status](https://travis-ci.org/idaviddesmet/NaCl.Core.svg?branch=master)](https://travis-ci.org/idaviddesmet/NaCl.Core)
[![NuGet](https://img.shields.io/nuget/v/NaCl.Core.svg)](https://www.nuget.org/packages/NaCl.Core/)
[![MyGet](https://img.shields.io/myget/nacl-core/v/NaCl.Core.svg)](https://www.myget.org/feed/nacl-core/package/nuget/NaCl.Core)
[![Maintenance](https://img.shields.io/maintenance/yes/2018.svg)](https://github.com/idaviddesmet/NaCl.Core)
[![License](https://img.shields.io/github/license/idaviddesmet/NaCl.Core.svg)](https://github.com/idaviddesmet/NaCl.Core/blob/master/LICENSE)
[![contributions welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](https://github.com/idaviddesmet/NaCl.Core/issues)

## Introduction

**NaCl.Core** is a managed-only cryptography library for [.NET](https://dot.net) which provides modern cryptographic _primitives_.

Currently supported:

- **ChaCha20**, a high-speed stream cipher based on Salsa20.
- **Poly1305**, a state-of-the-art secret-key message-authentication code (MAC).
- **ChaCha20-Poly1305**, an Authenticated Encryption with Associated Data (AEAD) algorithm; IETF variant as defined in [RFC8439](https://tools.ietf.org/html/rfc8439) and in its predecessor [RFC7539](https://tools.ietf.org/html/rfc7539).

Partially supported but requires more testing:

- **XChaCha20**, based on ChaCha20 IETF with extended nonce (192-bit instead of 96-bit).
- **XChaCha20-Poly1305**, a variant of ChaCha20-Poly1305 that utilizes the XChaCha20 construction in place of ChaCha20.

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
