using System;

namespace Intiq.Client.EnrollmentIdentity.Domain.Dto;

public class PlainTextData
{
    public byte[] Data { get; set; } = Array.Empty<byte>();
}