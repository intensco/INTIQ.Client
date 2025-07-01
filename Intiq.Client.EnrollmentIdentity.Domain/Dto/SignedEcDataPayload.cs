using System;

namespace Intiq.Client.EnrollmentIdentity.Domain.Dto;

public class SignedEcDataPayload
{
    public byte[] Data { get; set; } = Array.Empty<byte>();

    public byte[] R { get; set; } = Array.Empty<byte>();

    public byte[] S { get; set; } = Array.Empty<byte>();
}