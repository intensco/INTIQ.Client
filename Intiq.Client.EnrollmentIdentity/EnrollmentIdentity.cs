using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using Intiq.Client.EnrollmentIdentity.Configuration;
using Intiq.Shared.Common.V1;
using Intiq.SystemGateways.EnrollmentAuthority.Authority.V2;
using Intiq.SystemGateways.EnrollmentAuthority.Encrypted.V2;
using Microsoft.Extensions.Options;
using Polly;
using EnrollmentEntity = Intiq.SystemGateways.EnrollmentAuthority.Common.V2.EnrollmentEntity;
using EnrollmentEntityDescriptor = Intiq.SystemGateways.EnrollmentAuthority.Common.V2.EnrollmentEntityDescriptor;

namespace Intiq.Client.EnrollmentIdentity;

/// <summary>
/// Implementation of <see cref="IEnrollmentIdentity"/> that uses .NET native methods for cryptography.
/// </summary>
public class EnrollmentIdentity : IEnrollmentIdentity
{
    private readonly IEnrollmentEncryptionHandler _enrollmentEncryptionHandler;
    private readonly EnrollmentOptions _options;

    private readonly SemaphoreSlim _lock = new(1, 1);
    private long? _currentOutboxPosition;

    public const int MaxEntitiesPerToken = 50;

    public EnrollmentIdentity(
        IEnrollmentEncryptionHandler enrollmentEncryptionHandler,
        IOptions<EnrollmentOptions> options)
    {
        _enrollmentEncryptionHandler = enrollmentEncryptionHandler;
        _options = options.Value;
    }

    public async Task<IEnrollIdentityRequest> BuildCertificateSigningRequestAsync(CancellationToken cancellationToken = default)
    {
        if (_options.EnrollmentIdentity?.Id == default)
        {
            throw new InvalidOperationException("Missing EnrollmentIdentity ID configuration");
        }

        return await _enrollmentEncryptionHandler.BuildCertificateSigningRequestAsync(cancellationToken);
    }

    public async Task<IEnrollIdentityItemResponse> EnrollAsync(IEnrollIdentityRequest request, CancellationToken cancellationToken = default)
    {
        var enrollIdentityResponse = await Policy
            .HandleResult<IEnrollIdentityItemResponse?>(response => response == null || response.Status == EnrollIdentityStatusEnum.PendingApproval)
            .Or<Exception>()
            .WaitAndRetryForeverAsync(_ => TimeSpan.FromSeconds(10))
            .ExecuteAsync(async token =>
            {
                IEnrollIdentityItemResponse? innerResponse = null;
                var enrollIdentityCall = _enrollmentEncryptionHandler.EnrollIdentity(request, cancellationToken: cancellationToken);
                await foreach (var enrollIdentityResponse in enrollIdentityCall.WithCancellation(token))
                {
                    if (enrollIdentityResponse.FinalMessage != null && enrollIdentityResponse.FinalMessage.Value)
                    {
                        innerResponse = enrollIdentityResponse;
                    }
                }
                return innerResponse;
            }, cancellationToken);

        if (enrollIdentityResponse == null)
        {
            throw new InvalidOperationException("Failed to enroll.");
        }

        if (enrollIdentityResponse.Status == EnrollIdentityStatusEnum.Active && enrollIdentityResponse.IssuedCertificate != null)
        {
            ImportCertificate(enrollIdentityResponse.IssuedCertificate);
        }

        return enrollIdentityResponse;
    }

    public void ImportKeyPairs(CryptographyKeys keys)
    {
        _enrollmentEncryptionHandler.ImportKeyPairs(keys);
    }

    public void ImportCertificate(CertificateData certificate)
    {
        _enrollmentEncryptionHandler.ImportCertificate(certificate);
    }

    public async Task<AuthTokens> GetTokensAsync(
        EnrollmentEntityDescriptor[] entities,
        EnrollmentIdentityScopesEnum[] scopes,
        CancellationToken cancellationToken = default)
    {
        if (entities.Length > MaxEntitiesPerToken)
        {
            throw new ArgumentOutOfRangeException(nameof(entities), FormattableString.Invariant($"Maximum allowed entities per token is {MaxEntitiesPerToken}"));
        }

        return await _enrollmentEncryptionHandler.GetAuthTokenAsync(entities, scopes, cancellationToken);
    }

    public async Task<TokenData> RefreshAccessTokenAsync(TokenData refreshToken, CancellationToken cancellationToken = default)
    {
        return await _enrollmentEncryptionHandler.RefreshAuthTokenAsync(refreshToken, cancellationToken);
    }

    public async Task<EnrollmentEntity[]> RegisterEntitiesAsync(EnrollmentEntityDescriptor[] entities, CancellationToken cancellationToken = default)
    {
        var registeredEntities = await _enrollmentEncryptionHandler.RegisterEntitiesAsync(entities, cancellationToken);

        return registeredEntities.Entities.ToArray();
    }

    public async IAsyncEnumerable<OutboxEntity> GetEntitiesAsync(long? outboxPosition, [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        // set current position
        try
        {
            await _lock.WaitAsync(cancellationToken);

            _currentOutboxPosition = outboxPosition;
        }
        finally
        {
            _lock.Release();
        }

        while (!cancellationToken.IsCancellationRequested)
        {
            long? currentPosition;
            try
            {
                await _lock.WaitAsync(cancellationToken);

                currentPosition = _currentOutboxPosition;
            }
            finally
            {
                _lock.Release();
            }

            var eventVersionInfo = currentPosition.HasValue
                ? new EventVersionInfo { EventVersionInfo_ = currentPosition.Value }
                : new EventVersionInfo { EventVersionInfo_ = 0 };

            using var call = _enrollmentEncryptionHandler.GetEntities(cancellationToken);

            await call.WriteAsync(new GetEntitiesItemRequest
            {
                EventVersionInfo = eventVersionInfo
            }, cancellationToken);

            // in case of disconnection channel is completed, and we need to start over with next loop
            await foreach (var item in call.ReadAllAsync(cancellationToken))
            {
                if (item.Entity == null || item.EventVersionInfo?.EventVersionInfo_ == null)
                {
                    continue;
                }

                var position = item.EventVersionInfo.EventVersionInfo_;

                yield return new OutboxEntity(item.Entity, position);

                await TryConfirmEntityAsync(position, call, cancellationToken);
            }
        }
    }

    public async Task<IRefreshEnrolledIdentityRequest> BuildRefreshEnrolledIdentityRequestAsync(CryptographyKeys refreshKeys,
        CancellationToken cancellationToken = default)
    {
        var request = await _enrollmentEncryptionHandler.BuildRefreshEnrolledIdentityRequestAsync(refreshKeys, cancellationToken);
        return request;
    }

    public async Task<CertificateData> RefreshEnrolledIdentityAsync(IRefreshEnrolledIdentityRequest request,
        CancellationToken cancellationToken = default)
    {
        var response  = await _enrollmentEncryptionHandler.RefreshEnrolledIdentityAsync(request, cancellationToken);
        return response;
    }

    public async Task ConfirmEnrolledIdentityAsync(CertificateData newCertificate, CancellationToken cancellationToken = default)
    {
        await _enrollmentEncryptionHandler.ConfirmEnrolledIdentityAsync(newCertificate, cancellationToken);
    }

    private async Task TryConfirmEntityAsync(
        long outboxPosition,
        IDuplexStream<GetEntitiesItemRequest, IGetEntitiesItemResponse> getEntitiesCall,
        CancellationToken cancellationToken = default)
    {
        var getEntitiesRequest = new GetEntitiesItemRequest
        {
            ConfirmedEventVersionInfo = new EventVersionInfo
            {
                EventVersionInfo_ = outboxPosition,
            }
        };

        await getEntitiesCall.WriteAsync(getEntitiesRequest, cancellationToken);
    }
}