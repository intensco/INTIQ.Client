using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Intiq.SystemGateways.EnrollmentAuthority.Authority.V2;
using Intiq.SystemGateways.EnrollmentAuthority.Common.V2;
using Intiq.SystemGateways.EnrollmentAuthority.Encrypted.V2;

namespace Intiq.Client.EnrollmentIdentity;

public interface IEnrollmentEncryptionHandler
{
    void ImportKeyPairs(CryptographyKeys keyPairs);
    void ImportCertificate(CertificateData issuedCertificate);

    IAsyncEnumerable<IEnrollIdentityItemResponse> EnrollIdentity(IEnrollIdentityRequest request, CancellationToken cancellationToken = default);

    Task<AuthTokens> GetAuthTokenAsync(
        EnrollmentEntityDescriptor[] entities,
        EnrollmentIdentityScopesEnum[] scopes,
        CancellationToken cancellationToken = default);

    Task<TokenData> RefreshAuthTokenAsync(TokenData refreshToken, CancellationToken cancellationToken);

    Task<RegisteredEntitiesData> RegisterEntitiesAsync(EnrollmentEntityDescriptor[] entities, CancellationToken cancellationToken = default);
    IDuplexStream<GetEntitiesItemRequest, IGetEntitiesItemResponse> GetEntities(CancellationToken cancellationToken = default);
    Task<IEnrollIdentityRequest> BuildCertificateSigningRequestAsync(CancellationToken cancellationToken = default);
    Task<IRefreshEnrolledIdentityRequest> BuildRefreshEnrolledIdentityRequestAsync(CryptographyKeys refreshKeys, CancellationToken cancellationToken = default);
    Task<CertificateData> RefreshEnrolledIdentityAsync(IRefreshEnrolledIdentityRequest request, CancellationToken cancellationToken = default);
    Task ConfirmEnrolledIdentityAsync(CertificateData newCertificate, CancellationToken cancellationToken = default);
}