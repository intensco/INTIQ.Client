using System.Security.Cryptography;

namespace Intiq.Client.EnrollmentIdentity.Cryptography.Native;

public static class RsaCryptographyKeysHelpers
{
    public static RSA CreateRsa(string keyPair)
    {
        var rsa = RSA.Create();
        rsa.ImportFromPem(keyPair);
        return rsa;
    }
}