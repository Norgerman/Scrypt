Scrypt
=========
[![NuGet](https://img.shields.io/nuget/v/Norgerman.Cryptography.Scrypt.svg)](https://www.nuget.org/packages/Norgerman.Cryptography.Scrypt/)


Scrypt implementation for .Net

License [MIT](./LICENSE)

Usage

```csharp
var result = ScryptUtil.Scrypt(password, salt, N, r, p, dklen);
```