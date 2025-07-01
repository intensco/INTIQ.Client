using Intiq.Client.EnrollmentIdentity.Cryptography;

namespace Intiq.Client.EnrollmentIdentity;

/// <summary>
/// Structure to hold EC encryption and verification keypair.
/// </summary>
/// <param name="EncryptionKeyPair">Encryption key pair</param>
/// <param name="VerificationKeyPair">Verification key pair</param>
public readonly record struct EcCryptographyKeys(IEcEncryptionKeyPairHandle EncryptionKeyPair, IEcVerificationKeyPairHandle VerificationKeyPair);