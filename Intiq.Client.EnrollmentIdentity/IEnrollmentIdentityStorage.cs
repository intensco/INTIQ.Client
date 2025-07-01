using System;
using System.Collections;
using System.Threading;
using System.Threading.Tasks;
using Intiq.SystemGateways.EnrollmentAuthority.Authority.V2;

namespace Intiq.Client.EnrollmentIdentity;

public interface IEnrollmentIdentityStorage
{
    Task StoreKeyPairsAsync(CryptographyKeys cryptographyKeys, Guid enrollmentIdentityId, CancellationToken cancellationToken = default);
    Task<CryptographyKeys?> TryGetKeyPairsAsync(Guid enrollmentIdentityId, CancellationToken cancellationToken = default);

    Task StoreCertificateAsync(CertificateData certificate, Guid enrollmentIdentityId, CancellationToken cancellationToken = default);
    Task<CertificateData?> TryGetCertificateAsync(Guid enrollmentIdentityId, CancellationToken cancellationToken = default);

    Task StoreCertificateSigningRequestAsync(IEnrollIdentityRequest certificateSigningRequest, Guid enrollmentIdentityId, CancellationToken cancellationToken = default);
    Task<IEnrollIdentityRequest?> TryGetCertificateSigningRequestAsync(Guid enrollmentIdentityId, CancellationToken cancellationToken = default);

    Task StorePendingCertificateAsync(CertificateData certificate, CryptographyKeys keys, Guid enrollmentIdentityId, CancellationToken cancellationToken = default);
    Task ConfirmPendingCertificateAsync(Guid enrollmentIdentityId, CancellationToken cancellationToken = default);
    Task<(CertificateData PendingCertificate, CryptographyKeys Keys)?> TryGetPendingCertificateAsync(Guid enrollmentIdentityId, CancellationToken cancellationToken = default);
}