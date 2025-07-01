using System;

namespace Intiq.Client.EnrollmentIdentity.Domain.Dto;

public class EncryptedEcData
{ 
    public byte[] Data { get; set; } = Array.Empty<byte>();

    public byte[] Nonce { get; set; } = Array.Empty<byte>();

    public byte[] Tag { get; set; } = Array.Empty<byte>();

    public byte[] EncryptedSymmetricKey { get; set; } = Array.Empty<byte>();

    public byte[] KeyAuthenticationTag { get; set; } = Array.Empty<byte>();

    public required EcPublicKeyData EphemeralPublicKey { get; set; }
}