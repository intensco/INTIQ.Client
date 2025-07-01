using Intiq.Client.EnrollmentIdentity.Cryptography;

namespace Intiq.Client.EnrollmentIdentity;

/// <summary>
/// Structure to hold RSA encryption and verification keypair.
/// </summary>
/// <param name="EncryptionKeyPair">Encryption key pair</param>
/// <param name="VerificationKeyPair">Verification key pair</param>
public readonly record struct RsaCryptographyKeys(IRsaEncryptionKeyPairHandle EncryptionKeyPair, IRsaVerificationKeyPairHandle VerificationKeyPair);