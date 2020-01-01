# NaCl.Core, a cryptography library for .NET

[![Build Status](https://dev.azure.com/idaviddesmet/NaCl.Core/_apis/build/status/idaviddesmet.NaCl.Core)](https://dev.azure.com/idaviddesmet/NaCl.Core/_build/latest?definitionId=1)
[![Build status](https://ci.appveyor.com/api/projects/status/2k3cxt2e1r2jyinx?svg=true)](https://ci.appveyor.com/project/idaviddesmet/nacl-core)
[![Build Status](https://travis-ci.org/idaviddesmet/NaCl.Core.svg?branch=master)](https://travis-ci.org/idaviddesmet/NaCl.Core)
[![Dependabot Status](https://api.dependabot.com/badges/status?host=github&repo=idaviddesmet/NaCl.Core)](https://dependabot.com)
[![Maintenance](https://img.shields.io/maintenance/yes/2020.svg)](https://github.com/idaviddesmet/NaCl.Core)
[![contributions welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](https://github.com/idaviddesmet/NaCl.Core/issues)

## Introduction

**NaCl.Core** is a managed-only cryptography library for [.NET](https://dot.net) which provides modern cryptographic _primitives_.

#### Currently supported:

| Crypto | Description |
|--------|-------------|
| **ChaCha20** | A high-speed stream cipher based on Salsa20 |
| **XChaCha20** | Based on ChaCha20 IETF with extended nonce (192-bit instead of 96-bit) |
| **Poly1305** | A state-of-the-art secret-key message-authentication code (MAC) based on [RFC8439](https://tools.ietf.org/html/rfc8439) |
| **ChaCha20Poly1305** | An Authenticated Encryption with Associated Data (AEAD) algorithm; IETF variant as defined in [RFC8439](https://tools.ietf.org/html/rfc8439) and in its predecessor [RFC7539](https://tools.ietf.org/html/rfc7539) |
| **XChaCha20Poly1305** | A variant of ChaCha20-Poly1305 that utilizes the XChaCha20 construction in place of ChaCha20; as defined in the [RFC Draft](https://tools.ietf.org/html/draft-arciszewski-xchacha-03) |

## Installation

[![NuGet](https://img.shields.io/nuget/v/NaCl.Core.svg)](https://www.nuget.org/packages/NaCl.Core/)
[![MyGet](https://img.shields.io/myget/nacl-core/v/NaCl.Core.svg)](https://www.myget.org/feed/nacl-core/package/nuget/NaCl.Core)

Install the NaCl.Core NuGet package from the .NET Core CLI using:
```
dotnet add package NaCl.Core
```

or from the NuGet package manager:
```
Install-Package NaCl.Core
```

Or alternatively, you can add the NaCl.Core package from within Visual Studio's NuGet package manager.

Daily NuGet builds of the project are also available in the [MyGet](https://www.myget.org/feed/nacl-core/package/nuget/NaCl.Core) feed:

> [https://www.myget.org/F/nacl-core/api/v3/index.json](https://www.myget.org/F/nacl-core/api/v3/index.json)

## Usage

[![](https://img.shields.io/nuget/dt/NaCl.Core.svg)](https://www.nuget.org/packages/NaCl.Core/)

#### Symmetric Key Encryption

```csharp
// Create the primitive
var aead = new ChaCha20Poly1305(key);

// Use the primitive to encrypt a plaintext
var ciphertext = aead.Encrypt(plaintext, aad, nonce);

// ... or to decrypt a ciphertext
var output = aead.Decrypt(ciphertext, aad, nonce);
```

#### MAC (Message Authentication Code)

```csharp
// Use the primitive to compute a tag
var tag = Poly1305.ComputeMac(key, data);

// ... or to verify a tag
Poly1305.VerifyMac(key, data, tag);
```

## Test Coverage

[![Azure DevOps tests](https://img.shields.io/azure-devops/tests/idaviddesmet/NaCl.Core/1.svg?compact_message=)](https://dev.azure.com/idaviddesmet/NaCl.Core/_build/latest?definitionId=1)
[![Azure DevOps coverage](https://img.shields.io/azure-devops/coverage/idaviddesmet/NaCl.Core/1.svg)](https://dev.azure.com/idaviddesmet/NaCl.Core/_build/latest?definitionId=1)

- Includes the mandatory RFC [test vectors](https://github.com/idaviddesmet/NaCl.Core/tree/master/src/NaCl.Core.Tests).
- [Project Wycheproof](https://github.com/google/wycheproof) by members of Google Security Team, for testing against known attacks (when applicable).

## Learn More

[![License](https://img.shields.io/github/license/idaviddesmet/NaCl.Core.svg)](https://github.com/idaviddesmet/NaCl.Core/blob/master/LICENSE)

- [ChaCha, a variant of Salsa20](http://cr.yp.to/chacha/chacha-20080128.pdf) by Daniel J. Bernstein.
- [The Poly1305-AES message-authentication code](http://cr.yp.to/mac/poly1305-20050329.pdf) by Daniel J. Bernstein.
- [ChaCha20 and Poly1305 for IETF Protocols](https://tools.ietf.org/html/rfc8439) RFC.
- [XSalsa20](https://cr.yp.to/snuffle/xsalsa-20110204.pdf), an extended-nonce Salsa20 variant used in [NaCl](https://nacl.cr.yp.to).
- [XChaCha20-Poly1305](https://tools.ietf.org/html/draft-arciszewski-xchacha-02), an extended-nonce ChaCha20-Poly1305 IETF variant.
