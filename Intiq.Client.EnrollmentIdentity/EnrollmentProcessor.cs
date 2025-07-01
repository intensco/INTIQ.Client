using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Intiq.Client.EnrollmentIdentity.Configuration;
using Intiq.Client.EnrollmentIdentity.Encryption;
using Intiq.Client.EnrollmentIdentity.Exceptions;
using Intiq.SystemGateways.EnrollmentAuthority.Authority.V2;
using Intiq.SystemGateways.EnrollmentAuthority.Common.V2;
using Intiq.SystemGateways.EnrollmentAuthority.Encrypted.V2;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using EnrollmentEntityDescriptor = Intiq.SystemGateways.EnrollmentAuthority.Common.V2.EnrollmentEntityDescriptor;

namespace Intiq.Client.EnrollmentIdentity;

public class EnrollmentProcessor : IEnrollmentProcessor
{
    private readonly IEnrollmentIdentity _enrollmentIdentity;
    private readonly IEnrollmentIdentityStorage _enrollmentIdentityStorage;
    private readonly IEnrollmentEntitiesStorage _enrollmentEntitiesStorage;
    private readonly IKeyPairGenerator _keyPairGenerator;
    private readonly ILogger<EnrollmentProcessor> _logger;
    private readonly EnrollmentOptions _options;

    private bool _isEnrolled;
    private DateTime _certificateRefreshTime;
    private readonly SemaphoreSlim _enrollmentSemaphore = new(1, 1);

    private readonly ConcurrentDictionary<string, KeyHolder> _keyByEntityId = new();
    private readonly ConcurrentDictionary<string, AuthTokens> _authTokensByKey = new();
    private KeyHolder? _notFullKeyHolder;
    private readonly Channel<string> _tokenRefreshRequests = Channel.CreateUnbounded<string>();
    private readonly Task _tokenRefreshTask;
    private readonly CancellationTokenSource _tokenRefreshCancellationTokenSource = new();

    private readonly Dictionary<string, EnrollmentEntityDescriptor> _descriptorsByEntityId = new();

    private readonly ConcurrentDictionary<string, Timer> _refreshTimersByKey = new();

    public EnrollmentProcessor(
        IEnrollmentIdentity enrollmentIdentity,
        IEnrollmentIdentityStorage enrollmentIdentityStorage,
        IEnrollmentEntitiesStorage enrollmentEntitiesStorage,
        IKeyPairGenerator keyPairGenerator,
        ILogger<EnrollmentProcessor> logger,
        IOptions<EnrollmentOptions> options)
    {
        _enrollmentIdentity = enrollmentIdentity;
        _enrollmentIdentityStorage = enrollmentIdentityStorage;
        _keyPairGenerator = keyPairGenerator;
        _logger = logger;
        _enrollmentEntitiesStorage = enrollmentEntitiesStorage;
        _options = options.Value;
        _certificateRefreshTime = DateTime.MinValue;

        _tokenRefreshTask = RefreshTokensAsync(_tokenRefreshCancellationTokenSource.Token);
    }

    public async Task EnsureIdentityIsEnrolledAsync(CancellationToken cancellationToken = default)
    {
        await _enrollmentSemaphore.WaitAsync(cancellationToken);
        try
        {
            await EnsureIdentityIsEnrolledFromLockedContextAsync(cancellationToken);
        }
        finally
        {
            _enrollmentSemaphore.Release();
        }
    }

    private async Task EnsureIdentityIsEnrolledFromLockedContextAsync(CancellationToken cancellationToken = default)
    {
        // must be called from locked context
        if (!_isEnrolled)
        {
            // migrate any pending certificate in case we would terminate process in the middle of migration
            await MigrateToPendingCertificateAsync(cancellationToken);
            await EnrollIdentityAsync(cancellationToken);
            _isEnrolled = true;
        }

        var needCertificateRefresh = _certificateRefreshTime < DateTime.UtcNow;
        if (needCertificateRefresh)
        {
            await RefreshCertificateAsync(cancellationToken);
        }
    }

    private async Task EnrollIdentityAsync(CancellationToken cancellationToken = default)
    {
        var enrollmentIdentityId = _options.EnrollmentIdentity?.Id ?? Guid.Empty;
        if (enrollmentIdentityId == default)
        {
            throw new InvalidOperationException("Enrollment identity ID must be configured");
        }

        var keyPairs = await _enrollmentIdentityStorage.TryGetKeyPairsAsync(enrollmentIdentityId, cancellationToken);
        if (keyPairs == null)
        {
            keyPairs = _keyPairGenerator.GenerateKeyPairs();
            await _enrollmentIdentityStorage.StoreKeyPairsAsync(keyPairs.Value, enrollmentIdentityId, cancellationToken);
        }

        _enrollmentIdentity.ImportKeyPairs(keyPairs.Value);

        var certificate = await _enrollmentIdentityStorage.TryGetCertificateAsync(enrollmentIdentityId, cancellationToken);

        if (certificate == null)
        {
            await RequestNewCertificateAsync(cancellationToken);
        }
        else
        {
            _enrollmentIdentity.ImportCertificate(certificate);
            UpdateCertificateRefreshTime(certificate);
        }
    }

    private void UpdateCertificateRefreshTime(CertificateData certificateData)
    {
        var refreshTime = certificateData.ValidUntil.ToDateTime() - certificateData.IssuedAt.ToDateTime();
        if (refreshTime < TimeSpan.Zero)
        {
            _certificateRefreshTime = DateTime.MinValue;
        }

        refreshTime = TimeSpan.FromTicks(refreshTime.Ticks * 2 / 3);
        _certificateRefreshTime = certificateData.IssuedAt.ToDateTime() + refreshTime;
    }

    private async Task RefreshCertificateAsync(CancellationToken cancel = default)
    {
        var enrollmentIdentityId = _options.EnrollmentIdentity?.Id ?? Guid.Empty;
        if (enrollmentIdentityId == default)
        {
            throw new InvalidOperationException("Enrollment identity ID must be configured");
        }

        var refreshKeyPairs = _keyPairGenerator.GenerateKeyPairs();
        var refreshRequest = await _enrollmentIdentity.BuildRefreshEnrolledIdentityRequestAsync(refreshKeyPairs, cancel);
        var newCertificate = await _enrollmentIdentity.RefreshEnrolledIdentityAsync(refreshRequest, cancel);
        await _enrollmentIdentityStorage.StorePendingCertificateAsync(newCertificate, refreshKeyPairs, enrollmentIdentityId, cancel);
        await MigrateToPendingCertificateAsync(cancel);
    }

    private async Task MigrateToPendingCertificateAsync(CancellationToken cancel)
    {
        var enrollmentIdentityId = _options.EnrollmentIdentity?.Id ?? Guid.Empty;
        if (enrollmentIdentityId == default)
        {
            throw new InvalidOperationException("Enrollment identity ID must be configured");
        }

        var pendingCertificate = await _enrollmentIdentityStorage.TryGetPendingCertificateAsync(enrollmentIdentityId, cancel);
        if (pendingCertificate == null)
        {
            return;
        }

        try
        {
            await _enrollmentIdentity.ConfirmEnrolledIdentityAsync(pendingCertificate.Value.PendingCertificate, cancel);
        }
        catch (InvalidCertificateException)
        {
            _logger.LogWarning("Unable to confirm pending certificate. It must have been already confirmed. Continue migration.");
        }
        await _enrollmentIdentityStorage.ConfirmPendingCertificateAsync(enrollmentIdentityId, cancel);
        _enrollmentIdentity.ImportKeyPairs(pendingCertificate.Value.Keys);
        _enrollmentIdentity.ImportCertificate(pendingCertificate.Value.PendingCertificate);
        UpdateCertificateRefreshTime(pendingCertificate.Value.PendingCertificate);
    }

    private async Task RequestNewCertificateAsync(CancellationToken cancellationToken = default)
    {
        var enrollmentIdentityId = _options.EnrollmentIdentity?.Id ?? Guid.Empty;
        if (enrollmentIdentityId == default)
        {
            throw new InvalidOperationException("Enrollment identity ID must be configured");
        }

        var csr = await _enrollmentIdentityStorage.TryGetCertificateSigningRequestAsync(enrollmentIdentityId, cancellationToken);
        if (csr == null)
        {
            csr = await _enrollmentIdentity.BuildCertificateSigningRequestAsync(cancellationToken);
            await _enrollmentIdentityStorage.StoreCertificateSigningRequestAsync(csr, enrollmentIdentityId, cancellationToken);
        }

        var enrollResponse = await _enrollmentIdentity.EnrollAsync(csr, cancellationToken);

        var certificate = enrollResponse.IssuedCertificate!;
        await _enrollmentIdentityStorage.StoreCertificateAsync(certificate, enrollmentIdentityId, cancellationToken);
        UpdateCertificateRefreshTime(certificate);
    }

    private async Task RegisterEntitiesSafeAsync(EnrollmentEntityDescriptor[] entities, CancellationToken cancellationToken = default)
    {
        try
        {
            await _enrollmentIdentity.RegisterEntitiesAsync(entities, cancellationToken);
        }
        catch (InvalidCertificateException)
        {
            await RequestNewCertificateAsync(cancellationToken);
            await _enrollmentIdentity.RegisterEntitiesAsync(entities, cancellationToken);
        }
    }

    public async IAsyncEnumerable<(string entityId, EnrollEntityStatusEnum status)[]> WatchEntityStatusesAsync([EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var enrollmentIdentityId = _options.EnrollmentIdentity!.Id.ToString();

        var (outboxPosition, statuses) = await _enrollmentEntitiesStorage.GetEntityStatusesAsync(enrollmentIdentityId, cancellationToken);

        if (statuses.Count > 0)
        {
            yield return statuses.Select(kv => (entityId: kv.Key, status: kv.Value)).ToArray();
        }

        await foreach (var outboxResult in _enrollmentIdentity.GetEntitiesAsync(outboxPosition + 1, cancellationToken))
        {
            (string entityId, EnrollEntityStatusEnum status)[] result = [(entityId: outboxResult.Entity.Desc.Id, status: outboxResult.Entity.Status)];

            await _enrollmentEntitiesStorage.StoreEntityStatusesAsync(result, outboxResult.OutboxPosition, enrollmentIdentityId, cancellationToken);

            yield return result;
        }
    }

    public async Task<string> GetEntityBearerTokenAsync(string entityId, CancellationToken cancellationToken = default)
    {
        var token = await TryGetEntityBearerTokenAsync(entityId, cancellationToken);

        return token ?? throw new UnauthorizedEntityException($"Access token for entity '{entityId}' cannot be obtained. Entity must be authorized");
    }

    public async Task<string?> TryGetEntityBearerTokenAsync(string entityId, CancellationToken cancellationToken = default)
    {
        await _enrollmentSemaphore.WaitAsync(cancellationToken);
        try
        {
            await EnsureIdentityIsEnrolledFromLockedContextAsync(cancellationToken);

            var keyHolder = _keyByEntityId.GetValueOrDefault(entityId)
                            ?? throw new InvalidOperationException("Unable to get token for entity that were not registered yet. Entity ID: " + entityId);

            var authTokens = await GetAuthTokensForKeyHolderAsync(keyHolder, cancellationToken);

            if (authTokens.AuthorizedEntities.Any(e => e.Id == entityId))
            {
                return authTokens.AccessToken.Data;
            }

            return null;
        }
        finally
        {
            _enrollmentSemaphore.Release();
        }
    }

    private void InvalidateAuthTokensForKeyHolder(KeyHolder keyHolder)
    {
        _authTokensByKey.Remove(keyHolder.Key, out _);
    }

    private async Task<AuthTokens> GetAuthTokensForKeyHolderAsync(KeyHolder keyHolder, CancellationToken cancellationToken = default)
    {
        var cacheKey = keyHolder.Key;

        if (!_authTokensByKey.TryGetValue(cacheKey, out var authTokens))
        {
            var scopes = _options.EnrollmentIdentity!.Scopes;

            var entities = GetEnrollmentEntityDescriptors(keyHolder.EntityIds);

            authTokens = await GetTokensSafeAsync(entities, scopes, cancellationToken);

            _authTokensByKey.TryAdd(cacheKey, authTokens);

            ScheduleTokenRefresh(cacheKey, authTokens.AccessToken.Expiration.ToDateTime());
        }

        if (authTokens.AccessToken.Expiration.ToDateTime() < DateTime.UtcNow - TimeSpan.FromSeconds(10))
        {
            var accessToken = await RefreshAccessTokenSafeAsync(authTokens, cancellationToken);

            _authTokensByKey[cacheKey] = authTokens;

            authTokens.AccessToken = accessToken;
        }

        return authTokens;
    }

    private async Task<TokenData> RefreshAccessTokenSafeAsync(AuthTokens authTokens, CancellationToken cancellationToken = default)
    {
        try
        {
            return await _enrollmentIdentity.RefreshAccessTokenAsync(authTokens.RefreshToken!, cancellationToken);
        }
        catch (InvalidCertificateException)
        {
            await RequestNewCertificateAsync(cancellationToken);
            return await _enrollmentIdentity.RefreshAccessTokenAsync(authTokens.RefreshToken!, cancellationToken);
        }
    }

    private async Task<AuthTokens> GetTokensSafeAsync(EnrollmentEntityDescriptor[] entities, EnrollmentIdentityScopesEnum[] scopes, CancellationToken cancellationToken = default)
    {
        try
        {
            return await _enrollmentIdentity.GetTokensAsync(entities, scopes, cancellationToken);
        }
        catch (InvalidCertificateException)
        {
            await RequestNewCertificateAsync(cancellationToken);
            return await _enrollmentIdentity.GetTokensAsync(entities, scopes, cancellationToken);
        }
    }

    public async Task<IDictionary<string[], string>> GetEntityBearerTokensPerBucketAsync(IList<string> entityIds, CancellationToken cancellationToken = default)
    {
        await _enrollmentSemaphore.WaitAsync(cancellationToken);
        try
        {
            await EnsureIdentityIsEnrolledFromLockedContextAsync(cancellationToken);

            var keysByEntityIds = entityIds
                .Select(d => (deviceId: d, keyHolder: _keyByEntityId.GetValueOrDefault(d)))
                .GroupBy(x => x.keyHolder)
                .ToDictionary(g => g.Select(gg => gg.deviceId).ToArray(), g => g.Key);

            var result = new Dictionary<string[], string>();

            foreach (var (entityIdsForKey, keyHolder) in keysByEntityIds)
            {
                if (keyHolder == null)
                {
                    throw new InvalidOperationException("Unable to get token for entity(s) that were not registered yet. Entity IDs: " + string.Join(",", entityIdsForKey));
                }

                var token = await GetAuthTokensForKeyHolderAsync(keyHolder, cancellationToken);

                result.Add(token.AuthorizedEntities.Select(e => e.Id).ToArray(), token.AccessToken.Data);
            }

            return result;
        }
        finally
        {
            _enrollmentSemaphore.Release();
        }
    }

    public async Task RegisterEntitiesAsync(EnrollmentEntityDescriptor[] entities, CancellationToken cancellationToken = default)
    {
        await _enrollmentSemaphore.WaitAsync(cancellationToken);
        try
        {
            await EnsureIdentityIsEnrolledFromLockedContextAsync(cancellationToken);

            await RegisterEntitiesSafeAsync(entities, cancellationToken);

            HandleRegisteredEntities(entities);
        }
        finally
        {
            _enrollmentSemaphore.Release();
        }
    }

    private void HandleRegisteredEntities(EnrollmentEntityDescriptor[] entities)
    {
        foreach (var entity in entities)
        {
            _descriptorsByEntityId[entity.Id] = entity;
        }

        BucketizeEntitiesForTokens(entities.Select(e => e.Id));
    }

    private void BucketizeEntitiesForTokens(IEnumerable<string> entityIds)
    {
        foreach (var entityId in entityIds)
        {
            _keyByEntityId[entityId] = BucketizeEntityForTokens(entityId);
        }
    }

    private KeyHolder BucketizeEntityForTokens(string entityId)
    {
        if (_notFullKeyHolder == null)
        {
            _notFullKeyHolder = new KeyHolder
            {
                Key = entityId
            };
        }
        else
        {
            _notFullKeyHolder.Key += "_" + entityId;
        }

        var keyHolder = _notFullKeyHolder;

        _notFullKeyHolder.EntityIds.Add(entityId);

        InvalidateAuthTokensForKeyHolder(_notFullKeyHolder);

        if (_notFullKeyHolder.EntityIds.Count == EnrollmentIdentity.MaxEntitiesPerToken)
        {
            _notFullKeyHolder = null;
        }

        return keyHolder;
    }

    private EnrollmentEntityDescriptor[] GetEnrollmentEntityDescriptors(IEnumerable<string> entityIds)
    {
        return entityIds
            .Select(d => _descriptorsByEntityId[d])
            .ToArray();
    }

    private void ScheduleTokenRefresh(string cacheKey, DateTime expiration)
    {
        var diff = expiration - DateTime.UtcNow;

        if (diff < TimeSpan.Zero)
        {
            return;
        }

        var refreshIn = diff * 2 / 3;

        ScheduleTokenRefreshIn(refreshIn, cacheKey);
    }

    private void ScheduleTokenRefreshIn(TimeSpan refreshIn, string cacheKey)
    {
        _refreshTimersByKey.AddOrUpdate(
            cacheKey,
            _ =>
            {
                return new Timer(_ =>
                    {
                        _tokenRefreshRequests.Writer.TryWrite(cacheKey);

                        if (_refreshTimersByKey.TryRemove(cacheKey, out var timer))
                        {
                            timer.Dispose();
                        }
                    },
                    null,
                    refreshIn,
                    Timeout.InfiniteTimeSpan);
            },
            (_, oldTimer) =>
            {
                oldTimer.Change(refreshIn, Timeout.InfiniteTimeSpan);
                return oldTimer;
            });
    }

    private async Task RefreshTokensAsync(CancellationToken cancellationToken = default)
    {
        await foreach (var cacheKey in _tokenRefreshRequests.Reader.ReadAllAsync(cancellationToken))
        {
            await _enrollmentSemaphore.WaitAsync(cancellationToken);
            try
            {
                if (!_authTokensByKey.TryGetValue(cacheKey, out var authTokens))
                {
                    continue;
                }

                var accessToken = await _enrollmentIdentity.RefreshAccessTokenAsync(authTokens.RefreshToken!, cancellationToken);

                authTokens.AccessToken = accessToken;
            }
            catch (Exception e)
            {
                _logger.LogWarning(e, "Unable to refresh access token. Will be retried in a while");

                ScheduleTokenRefreshIn(TimeSpan.FromSeconds(5), cacheKey);
            }
            finally
            {
                _enrollmentSemaphore.Release();
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        _tokenRefreshCancellationTokenSource.Cancel();
        await Task.WhenAny(_tokenRefreshTask);

        foreach (var timer in _refreshTimersByKey.Values)
        {
            await timer.DisposeAsync();
        }
    }
}