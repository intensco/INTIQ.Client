using Intiq.Client.EnrollmentIdentity.Cryptography;

namespace Intiq.Client.EnrollmentIdentity;

/// <summary>
/// Structure to hold encryption and verification keypair.
/// </summary>
/// <param name="EncryptionKeyPair">Encryption key pair</param>
/// <param name="VerificationKeyPair">Verification key pair</param>
public readonly record struct CryptographyKeys(IKeyPairHandle EncryptionKeyPair, IKeyPairHandle VerificationKeyPair);