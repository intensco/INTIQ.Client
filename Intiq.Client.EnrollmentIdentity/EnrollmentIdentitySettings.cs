using System;
using Intiq.SystemGateways.EnrollmentAuthority.Encrypted.V2;

namespace Intiq.Client.EnrollmentIdentity;

public class EnrollmentIdentitySettings
{
    /// <summary>
    /// Gets or sets enrollment identity id.
    /// </summary>
    public Guid Id { get; set; }

    /// <summary>
    /// Gets or sets contract ID for better look up in UI. It is optional parameter.
    /// </summary>
    public Guid? ContractId { get; set; }

    /// <summary>
    /// Gets or sets human readable title for Enrollment Identity
    /// </summary>
    public string? Title { get; set; }

    /// <summary>
    /// Gets or sets Enrollment Identity type
    /// </summary>
    public EnrollmentIdentityTypeEnum Type { get; set; }

    /// <summary>
    /// Gets or sets Enrollment Identity scopes (permissions).
    /// </summary>
    public EnrollmentIdentityScopesEnum[] Scopes { get; set; } = Array.Empty<EnrollmentIdentityScopesEnum>();

    /// <summary>
    /// Gets or sets operating region. It is required to set at least country code in ISO 3166-1/Alpha-2.
    /// </summary>
    public EnrollmentIdentityOperatingRegion? OperatingRegion { get; set; }
}