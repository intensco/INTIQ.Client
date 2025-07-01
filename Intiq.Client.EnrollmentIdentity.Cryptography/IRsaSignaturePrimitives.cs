using Intiq.Client.EnrollmentIdentity.Domain.Dto;
using Intiq.Client.EnrollmentIdentity.Domain.Enums;

namespace Intiq.Client.EnrollmentIdentity.Cryptography;

public interface IRsaSignaturePrimitives
{
    IRsaVerificationKeyPairHandle GenerateKeyPair();

    IRsaVerificationKeyPairHandle DeserializeKeyPair(byte[] serializedKeyPair);

    bool Verify(SignedRsaData signedData);

    SignedRsaData Sign(PlainTextData plainText, SupportedVerificationAlgorithms algorithm, IRsaVerificationKeyPairHandle verificationKeyPair);
}