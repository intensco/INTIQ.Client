using System;
using Intiq.SystemGateways.EnrollmentAuthority.Common.V2;

namespace Intiq.Client.EnrollmentIdentity.Configuration;

public class EnrollmentOptions
{
    /// <summary>
    /// Gets or sets certificate signing request title.
    /// It should contain unique text for better identification during approval process.
    /// </summary>
    public string? CsrTitle { get; set; }

    /// <summary>
    /// Gets or sets enrollment identity configuration.
    /// </summary>
    public EnrollmentIdentitySettings? EnrollmentIdentity { get; set; }

    /// <summary>
    /// Gets or sets entities that should be preregistered during Certificate Signing Request approval.
    /// </summary>
    public EnrollmentEntityDescriptor[] Entities { get; set; } = Array.Empty<EnrollmentEntityDescriptor>();

    public EnrollmentEncryptionType EnrollmentEncryptionType { get; set; } = EnrollmentEncryptionType.Ec;
}