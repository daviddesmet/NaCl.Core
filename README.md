# NaCl.Core, a cryptography library for .NET

[![Build status](https://ci.appveyor.com/api/projects/status/2k3cxt2e1r2jyinx?svg=true)](https://ci.appveyor.com/project/idaviddesmet/nacl-core)
[![Build Status](https://travis-ci.org/idaviddesmet/NaCl.Core.svg?branch=master)](https://travis-ci.org/idaviddesmet/NaCl.Core)
[![NuGet](https://img.shields.io/nuget/v/NaCl.Core.svg)](https://www.nuget.org/packages/NaCl.Core/)
[![MyGet](https://img.shields.io/myget/nacl-core/v/NaCl.Core.svg)](https://www.myget.org/feed/nacl-core/package/nuget/NaCl.Core)
[![Maintenance](https://img.shields.io/maintenance/yes/2018.svg)](https://github.com/idaviddesmet/NaCl.Core)
[![License](https://img.shields.io/github/license/idaviddesmet/NaCl.Core.svg)](https://github.com/idaviddesmet/NaCl.Core/blob/master/LICENSE)
[![contributions welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](https://github.com/idaviddesmet/NaCl.Core/issues)

## Introduction

**NaCl.Core** is a managed-only cryptographic library for [.NET](https://dot.net) which provides modern cryptographic _primitives_.

Currently supported:

* **ChaCha20**, a high-speed stream cipher based on Salsa20
* **Poly1305**, a state-of-the-art secret-key message-authentication
* **ChaCha20-Poly1305**, an Authenticated Encryption with Associated Data (AEAD) algorithm

Partially supported but requires more testing:

* **XChaCha20**, based on ChaCha20 IETF with extended nonce
* **XChaCha20-Poly1305**, an IETF variant of ChaCha20-Poly1305

## Learn More

*   [ChaCha, a variant of Salsa20](http://cr.yp.to/chacha/chacha-20080128.pdf) by Daniel J. Bernstein
*   [The Poly1305-AES message-authentication code](http://cr.yp.to/mac/poly1305-20050329.pdf) by Daniel J. Bernstein
*   [ChaCha20 and Poly1305 for IETF Protocols](https://tools.ietf.org/html/rfc7539)
