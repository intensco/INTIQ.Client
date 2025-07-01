using System;
using Google.Protobuf.WellKnownTypes;
using Intiq.Client.EnrollmentIdentity.Helpers;
using Intiq.SystemGateways.EnrollmentAuthority.Common.V2;
using Intiq.SystemGateways.EnrollmentAuthority.Encrypted.V2;

namespace Intiq.Client.EnrollmentIdentity.Encryption.EC;

public class EcCsrBuilder
{
    public CertificateSigningRequestEc BuildCertificateSigningRequest(
        string? csrTitle,
        EnrollmentIdentitySettings? identitySettings,
        EnrollmentEntityDescriptor[] entities,
        EcCryptographyKeys keyPairs)
    {
        if (string.IsNullOrWhiteSpace(csrTitle))
        {
            throw new ArgumentException(FormattableString.Invariant($"Missing CsrTitle configuration."));
        }

        if (identitySettings == null)
        {
            throw new ArgumentException(FormattableString.Invariant($"Missing Enrollment Identity configuration."));
        }

        if (string.IsNullOrWhiteSpace(identitySettings.Title))
        {
            throw new ArgumentException(FormattableString.Invariant($"Missing {nameof(EnrollmentIdentitySettings.Title)}"));
        }

        if (identitySettings.OperatingRegion == null)
        {
            throw new ArgumentException(FormattableString.Invariant($"Missing {nameof(EnrollmentIdentitySettings.OperatingRegion)}"));
        }

        if (identitySettings.OperatingRegion.Country == null)
        {
            throw new ArgumentException(FormattableString.Invariant($"Missing {nameof(EnrollmentIdentityOperatingRegion.Country)}"));
        }

        if (identitySettings.OperatingRegion.Country.Length != 2)
        {
            throw new ArgumentException(FormattableString.Invariant($"Invalid format of {nameof(EnrollmentIdentityOperatingRegion.Country)}"));
        }

        var utcNow = DateTime.UtcNow;
        var validFrom = utcNow - TimeSpan.FromDays(1); // common practice with certificates to avoid time issues
        var validTo = validFrom + TimeSpan.FromDays(365);
        var pkiEncryptionPublicKey = keyPairs.EncryptionKeyPair.GetEncryptionPublicKey();
        var pkiVerificationPublicKey = keyPairs.VerificationKeyPair.GetVerificationPublicKey();
        var encryptionPublicKey = pkiEncryptionPublicKey.ToProto();
        var verificationPublicKey = pkiVerificationPublicKey.ToProto();

        var csrData = new CertificateSigningRequestEcData
        {
            Id = identitySettings.Id.ToString(),
            CertRolloverAllowed = true,
            CreatedAt = Timestamp.FromDateTime(utcNow),
            ValidFrom = Timestamp.FromDateTime(validFrom),
            ValidTo = Timestamp.FromDateTime(validTo),
            Title = csrTitle,
            EnrollmentIdentity = new EnrollmentIdentityInfo
            {
                Title = identitySettings.Title,
                ContractId = identitySettings.ContractId.HasValue ? identitySettings.ContractId.ToString() : null,
                Id = identitySettings.Id.ToString(),
                OperatingRegion = identitySettings.OperatingRegion,
                Type = identitySettings.Type,
            },
            EncryptionPublicKey = encryptionPublicKey,
            VerificationPublicKey = verificationPublicKey,
        };
        csrData.EnrollmentIdentity.Scopes.AddRange(identitySettings.Scopes);
        csrData.Entities.AddRange(entities);

        return new CertificateSigningRequestEc
        {
            Data = csrData,
            Version = 1,
        };
    }
}