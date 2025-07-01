namespace Intiq.Client.EnrollmentIdentity.Domain.Dto;

public class SignedEcData
{
    public required SignedEcDataPayload SignedData { get; set; }

    public required EcVerificationPublicKey VerificationPublicKey { get; set; }
}