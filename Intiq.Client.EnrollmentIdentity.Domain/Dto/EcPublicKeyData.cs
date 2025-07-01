using System;

namespace Intiq.Client.EnrollmentIdentity.Domain.Dto;

public class EcPublicKeyData
{
    public EcCurveName CurveName { get; set; }
    public byte[] X { get; set; } = Array.Empty<byte>();
    public byte[] Y { get; set; } = Array.Empty<byte>();
}