using Intiq.Client.EnrollmentIdentity.Domain.Dto;
using Intiq.Client.EnrollmentIdentity.Domain.Enums;

namespace Intiq.Client.EnrollmentIdentity.Cryptography;

public interface IEcSignaturePrimitives
{
    IEcVerificationKeyPairHandle GenerateKeyPair();

    IEcVerificationKeyPairHandle DeserializeKeyPair(byte[] serializedKeyPair);

    bool Verify(SignedEcData signedData);

    SignedEcData Sign(PlainTextData plainText, SupportedVerificationAlgorithms algorithm, IEcVerificationKeyPairHandle verificationKeyPair);
}