using System;

namespace Intiq.Client.EnrollmentIdentity.Domain.Dto;

public class SignedRsaDataPayload
{
    public byte[] Data { get; set; } = Array.Empty<byte>();

    public byte[] Signature { get; set; } = Array.Empty<byte>();
}