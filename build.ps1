cd src\Norgerman.Cryptography.Scrypt
dotnet restore
dotnet build
dotnet build -c Release
dotnet pack -c Release