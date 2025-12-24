using System.Security.Cryptography;
using System.Buffers.Text;
using System.Text.Json;
using System.Text;

var header = new
{
    alg = "RS256",
    typ = "JWT"
};

var initiated = DateTimeOffset.UtcNow;
var expiring = initiated.AddHours(1);

var payload = new
{
    iat = initiated.ToUnixTimeSeconds(),
    exp = expiring.ToUnixTimeSeconds(),
    sub = Guid.NewGuid(),
    name = "Aaron Pina"
};

var headerJson = JsonSerializer.Serialize(header);
var headerBytes = Encoding.UTF8.GetBytes(headerJson);
var headerEncoded = Base64Url.EncodeToString(headerBytes);

var payloadJson = JsonSerializer.Serialize(payload);
var payloadBytes = Encoding.UTF8.GetBytes(payloadJson);
var payloadEncoded = Base64Url.EncodeToString(payloadBytes);

var input = $"{headerEncoded}.{payloadEncoded}";
var inputBytes = Encoding.ASCII.GetBytes(input);
var hash = SHA256.HashData(inputBytes);

using var rsa = RSA.Create(2048);

var signatureBytes = rsa.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
var signatureEncoded = Base64Url.EncodeToString(signatureBytes);

var jwt = $"{input}.{signatureEncoded}";

var publicKey = rsa.ExportRSAPublicKeyPem();

Console.WriteLine(jwt);
Console.WriteLine();
Console.WriteLine(publicKey);
