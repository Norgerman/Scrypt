Scrypt
=========
[![NuGet](https://img.shields.io/nuget/v/Norgerman.Cryptography.Scrypt.svg)](https://www.nuget.org/packages/Norgerman.Cryptography.Scrypt/)
![Build Status](https://github.com/orgerman/Scrypt/workflows/Build/badge.svg)
[![license](https://img.shields.io/github/license/mashape/apistatus.svg)](./LICENSE)
[![LICENSE](https://img.shields.io/badge/license-Anti%20996-blue.svg)](https://github.com/996icu/996.ICU/blob/master/LICENSE)


Scrypt implementation for .Net

Usage

```csharp
var result = ScryptUtil.Scrypt(password, salt, N, r, p, dklen);
```
