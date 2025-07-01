using System;

namespace Intiq.Client.EnrollmentIdentity.Domain.Dto;

public class EncryptedRsaDataPayload
{
    public byte[] Data { get; set; } = Array.Empty<byte>();

    public byte[] IV { get; set; } = Array.Empty<byte>();

    public byte[] EncryptedSymmetricKey { get; set; } = Array.Empty<byte>();
}