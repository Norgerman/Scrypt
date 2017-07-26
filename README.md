Scrypt
=========
[![NuGet](https://img.shields.io/nuget/v/Norgerman.Cryptography.Scrypt.svg)](https://www.nuget.org/packages/Norgerman.Cryptography.Scrypt/)
[![Build Status](https://ci.appveyor.com/api/projects/status/github/Norgerman/Scrypt?svg=true)](https://ci.appveyor.com/project/Norgerman/Scrypt)
[![license](https://img.shields.io/github/license/mashape/apistatus.svg)](./LICENSE)


Scrypt implementation for .Net

Usage

```csharp
var result = ScryptUtil.Scrypt(password, salt, N, r, p, dklen);
```
