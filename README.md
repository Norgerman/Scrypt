Scrypt
=========
[![NuGet](https://img.shields.io/nuget/v/Norgerman.Cryptography.Scrypt.svg)](https://www.nuget.org/packages/Norgerman.Cryptography.Scrypt/)
[![Build Status](https://ci.appveyor.com/api/projects/status/github/Norgerman/Scrypt?svg=true)](https://ci.appveyor.com/project/Norgerman/Scrypt)
[![license](https://img.shields.io/github/license/mashape/apistatus.svg)](./LICENSE)
[![LICENSE](https://img.shields.io/badge/license-NPL%20(The%20996%20Prohibited%20License)-blue.svg)](https://github.com/996icu/996.ICU/blob/master/LICENSE)


Scrypt implementation for .Net

Usage

```csharp
var result = ScryptUtil.Scrypt(password, salt, N, r, p, dklen);
```
