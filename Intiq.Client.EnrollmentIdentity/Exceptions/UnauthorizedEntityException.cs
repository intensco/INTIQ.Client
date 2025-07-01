using System;

namespace Intiq.Client.EnrollmentIdentity.Exceptions;

public class UnauthorizedEntityException : Exception
{
    public UnauthorizedEntityException(string? message) : base(message)
    {
    }
}