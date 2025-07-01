using System;

namespace Intiq.Client.EnrollmentIdentity.Domain.Dto;

public class RsaEncryptionPublicKeyData
{
    public byte[] Rsa { get; set; } = Array.Empty<byte>();
}