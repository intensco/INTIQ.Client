using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Intiq.SystemGateways.EnrollmentAuthority.Authority.V2;
using AuthTokens = Intiq.SystemGateways.EnrollmentAuthority.Encrypted.V2.AuthTokens;
using EnrollmentIdentityScopesEnum = Intiq.SystemGateways.EnrollmentAuthority.Encrypted.V2.EnrollmentIdentityScopesEnum;
using TokenData = Intiq.SystemGateways.EnrollmentAuthority.Encrypted.V2.TokenData;
using EnrollmentEntity = Intiq.SystemGateways.EnrollmentAuthority.Common.V2.EnrollmentEntity;
using EnrollmentEntityDescriptor = Intiq.SystemGateways.EnrollmentAuthority.Common.V2.EnrollmentEntityDescriptor;

namespace Intiq.Client.EnrollmentIdentity;

/// <summary>
/// Facade to communicate with Enrollment Authority
/// </summary>
public interface IEnrollmentIdentity
{
    void ImportKeyPairs(CryptographyKeys keys);
    void ImportCertificate(CertificateData certificate);

    /// <summary>
    /// Builds certificate signing request that is used in <see cref="Enroll"/> step.
    /// The result of this call should be persistently stored. It should be reused
    /// whenever we need to call <see cref="Enroll"/> multiple times (e.g. restarts).
    /// </summary>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<IEnrollIdentityRequest> BuildCertificateSigningRequestAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Enrolls Identity into Enrollment Authority. It is safe to call this method multiple times to restore
    /// communication or restore certificate.
    /// </summary>
    /// <param name="request"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<IEnrollIdentityItemResponse> EnrollAsync(IEnrollIdentityRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Requests authentication tokens by using issued certificate from Enroll step.
    /// </summary>
    /// <param name="entities"></param>
    /// <param name="scopes"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<AuthTokens> GetTokensAsync(
        EnrollmentEntityDescriptor[] entities,
        EnrollmentIdentityScopesEnum[] scopes,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Requests new access token by using refresh token.
    /// </summary>
    /// <param name="refreshToken"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<TokenData> RefreshAccessTokenAsync(TokenData refreshToken, CancellationToken cancellationToken = default);

    /// <summary>
    /// Enrolls new entities under this Enrollment Identity. It returns status of requested entities.
    /// </summary>
    /// <param name="entities"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<EnrollmentEntity[]> RegisterEntitiesAsync(EnrollmentEntityDescriptor[] entities, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets changes in entities from certain position in stream.
    /// To start from the beginning use stream position null.
    /// </summary>
    /// <param name="outboxPosition"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    IAsyncEnumerable<OutboxEntity> GetEntitiesAsync(long? outboxPosition, CancellationToken cancellationToken = default);

    /// <summary>
    /// Builds request to refresh enrolled identity.
    /// </summary>
    /// <param name="refreshKeys"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<IRefreshEnrolledIdentityRequest> BuildRefreshEnrolledIdentityRequestAsync(CryptographyKeys refreshKeys, CancellationToken cancellationToken = default);

    /// <summary>
    /// Requests certificate renewal. It returns new certificate.
    /// </summary>
    /// <param name="request"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<CertificateData> RefreshEnrolledIdentityAsync(IRefreshEnrolledIdentityRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Confirms that new certificate is going to be used for enrolled identity.
    /// </summary>
    /// <param name="newCertificate"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task ConfirmEnrolledIdentityAsync(CertificateData newCertificate, CancellationToken cancellationToken = default);
}