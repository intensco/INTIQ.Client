using System;

namespace Intiq.Client.EnrollmentIdentity.Domain.Dto;

public class RsaVerificationPublicKeyData
{
    public byte[] Rsa { get; set; } = Array.Empty<byte>();
}