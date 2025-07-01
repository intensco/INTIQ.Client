namespace Intiq.Client.EnrollmentIdentity.Domain.Dto;

public class SignedRsaData
{
    public required SignedRsaDataPayload SignedData { get; set; }

    public required RsaVerificationPublicKey VerificationPublicKey { get; set; }
}