using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Intiq.SystemGateways.EnrollmentAuthority.Authority.V2;

namespace Intiq.Client.EnrollmentIdentity;

public class MemoryEnrollmentIdentityStorage : IEnrollmentIdentityStorage
{
    private readonly Dictionary<Guid, CryptographyKeys> _keyPairsByIdentityId = new();
    private readonly Dictionary<Guid, CertificateData> _certificatesByIdentityId = new();
    private readonly Dictionary<Guid, IEnrollIdentityRequest> _csrsByIdentityId = new();
    private readonly Dictionary<Guid, (CertificateData, CryptographyKeys)> _pendingCertificatesByIdentityId = new();

    public async Task StoreKeyPairsAsync(CryptographyKeys cryptographyKeys, Guid enrollmentIdentityId, CancellationToken cancellationToken = default)
    {
        _keyPairsByIdentityId[enrollmentIdentityId] = cryptographyKeys;
    }

    public async Task<CryptographyKeys?> TryGetKeyPairsAsync(Guid enrollmentIdentityId, CancellationToken cancellationToken = default)
    {
        return _keyPairsByIdentityId.TryGetValue(enrollmentIdentityId, out var keys) ? keys : null;
    }

    public async Task StoreCertificateAsync(CertificateData certificate, Guid enrollmentIdentityId, CancellationToken cancellationToken = default)
    {
        _certificatesByIdentityId[enrollmentIdentityId] = certificate;
    }

    public async Task<CertificateData?> TryGetCertificateAsync(Guid enrollmentIdentityId, CancellationToken cancellationToken = default)
    {
        return _certificatesByIdentityId.GetValueOrDefault(enrollmentIdentityId);
    }

    public async Task StoreCertificateSigningRequestAsync(IEnrollIdentityRequest certificateSigningRequest, Guid enrollmentIdentityId, CancellationToken cancellationToken = default)
    {
        _csrsByIdentityId[enrollmentIdentityId] = certificateSigningRequest;
    }

    public async Task<IEnrollIdentityRequest?> TryGetCertificateSigningRequestAsync(Guid enrollmentIdentityId, CancellationToken cancellationToken = default)
    {
        return _csrsByIdentityId.GetValueOrDefault(enrollmentIdentityId);
    }

    public async Task StorePendingCertificateAsync(CertificateData certificate, CryptographyKeys keys, Guid enrollmentIdentityId, CancellationToken cancellationToken = default)
    {
        _pendingCertificatesByIdentityId[enrollmentIdentityId] = (certificate, keys);
    }

    public async Task ConfirmPendingCertificateAsync(Guid enrollmentIdentityId, CancellationToken cancellationToken = default)
    {
        if (_pendingCertificatesByIdentityId.TryGetValue(enrollmentIdentityId, out var pending))
        {
            _certificatesByIdentityId[enrollmentIdentityId] = pending.Item1;
            _keyPairsByIdentityId[enrollmentIdentityId] = pending.Item2;
            _pendingCertificatesByIdentityId.Remove(enrollmentIdentityId);
        }
    }

    public async Task<(CertificateData PendingCertificate, CryptographyKeys Keys)?> TryGetPendingCertificateAsync(Guid enrollmentIdentityId, CancellationToken cancellationToken = default)
    {
        return _pendingCertificatesByIdentityId.GetValueOrDefault(enrollmentIdentityId);
    }
}