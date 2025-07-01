using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Google.Protobuf;
using Grpc.Core;
using Intiq.Client.EnrollmentIdentity.Configuration;
using Intiq.Client.EnrollmentIdentity.Cryptography;
using Intiq.Client.EnrollmentIdentity.Enums;
using Intiq.Client.EnrollmentIdentity.Helpers;
using Intiq.SystemGateways.EnrollmentAuthority.Authority.V2;
using Intiq.SystemGateways.EnrollmentAuthority.Common.V2;
using Intiq.SystemGateways.EnrollmentAuthority.Encrypted.V2;
using Microsoft.Extensions.Options;

namespace Intiq.Client.EnrollmentIdentity.Encryption.RSA;

public class RsaEnrollmentEncryptionHandler : IEnrollmentEncryptionHandler
{
    private readonly EnrollmentAuthorityService.EnrollmentAuthorityServiceClient _enrollmentAuthorityClient;
    private readonly RsaCryptoPayloadProcessor _cryptoPayloadProcessor;
    private readonly EnrollmentOptions _options;

    private CertificateData? _certificate;
    private string? _certificateDataEncoded;
    private RsaCryptographyKeys? _keyPairs;

    private string CertificateDataEncoded
    {
        get
        {
            if (_certificateDataEncoded == null)
            {
                throw new InvalidOperationException("Certificate needs to be loaded first. Use ImportCertificateAsync first.");
            }

            return _certificateDataEncoded;
        }
    }

    public RsaEnrollmentEncryptionHandler(
        EnrollmentAuthorityService.EnrollmentAuthorityServiceClient enrollmentAuthorityClient,
        RsaCryptoPayloadProcessor cryptoPayloadProcessor,
        IOptions<EnrollmentOptions> options)
    {
        _enrollmentAuthorityClient = enrollmentAuthorityClient;
        _cryptoPayloadProcessor = cryptoPayloadProcessor;
        _options = options.Value;
    }

    private void CheckCertificate()
    {
        if (_certificate == null)
        {
            throw new InvalidOperationException("Certificate needs to be loaded first. Use ImportCertificateAsync first.");
        }
    }

    public void ImportKeyPairs(CryptographyKeys keyPairs)
    {
        _keyPairs = ToRsaCryptographyKeys(keyPairs);
    }

    public void ImportCertificate(CertificateData certificate)
    {
        _certificate = certificate;
        _certificateDataEncoded = Convert.ToBase64String(certificate.Data.Span);

        ValidateKeyPairsAndCertificate(certificate);
    }

    private void ValidateKeyPairsAndCertificate(CertificateData certificate)
    {
        if (!_keyPairs.HasValue)
        {
            throw new InvalidOperationException("Public keys needs to be imported at first");
        }

        var csr = DeserializeCsr(certificate);
        if (csr.Data?.EncryptionPublicKey?.Key.Rsa == null)
        {
            throw new InvalidOperationException("Missing encryption public key in certificate.");
        }

        if (csr.Data?.VerificationPublicKey?.Key.Rsa == null)
        {
            throw new InvalidOperationException("Missing verification public key in certificate.");
        }

        var encryptionKey = _keyPairs.Value.EncryptionKeyPair.GetEncryptionPublicKey();
        if (encryptionKey.Key.Rsa == null)
        {
            throw new InvalidOperationException("Missing encryption key.");
        }

        if (!encryptionKey.Key.Rsa.SequenceEqual(csr.Data.EncryptionPublicKey.Key.Rsa))
        {
            throw new InvalidOperationException("Certificate and encryption keypair mismatch.");
        }

        var verificationKey = _keyPairs.Value.VerificationKeyPair.GetVerificationPublicKey();
        if (verificationKey.Key.Rsa == null)
        {
            throw new InvalidOperationException("Missing verification key.");
        }

        if (!verificationKey.Key.Rsa.SequenceEqual(csr.Data.VerificationPublicKey.Key.Rsa))
        {
            throw new InvalidOperationException("Certificate and verification keypair mismatch.");
        }
    }

    private CertificateSigningRequestRsa DeserializeCsr(CertificateData certificate)
    {
        var signedData = certificate.Data.ToByteArray().ProtoDeserialize<SignedRsaData>();
        if (signedData.SignedData == null)
        {
            throw new InvalidOperationException("Missing signed data.");
        }

        return signedData.SignedData.Data.ToByteArray().ProtoDeserialize<CertificateSigningRequestRsa>();
    }

    public async IAsyncEnumerable<IEnrollIdentityItemResponse> EnrollIdentity(IEnrollIdentityRequest request, [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        if (request is not RsaEnrollIdentityRequest rsaRequest)
        {
            throw new NotSupportedException("This implementation supports only RSA requests.");
        }

        using var call = _enrollmentAuthorityClient.EnrollIdentityRsa(rsaRequest.Request, cancellationToken: cancellationToken);

        await foreach (var ecResponse in call.ResponseStream.ReadAllAsync(cancellationToken: cancellationToken))
        {
            yield return ecResponse;
        }
    }

    public async Task<AuthTokens> GetAuthTokenAsync(
        EnrollmentEntityDescriptor[] entities,
        EnrollmentIdentityScopesEnum[] scopes,
        CancellationToken cancellationToken = default)
    {
        CheckCertificate();
        if (!_keyPairs.HasValue)
        {
            throw new InvalidOperationException("No certificate nor public keys were imported");
        }

        var eaEncryptionPublicKey = await GetEaEncryptionPublicKeyInternalAsync(cancellationToken);
        var preparedChallengeData = await PrepareChallengeDataAsync(eaEncryptionPublicKey, _cryptoPayloadProcessor, cancellationToken);

        var authenticationTokenRequestData = new AuthTokenRequestRsaData
        {
            ChallengeData = preparedChallengeData.ChallengeData,
            Id = preparedChallengeData.ChallengeId.ToString(),
        };
        authenticationTokenRequestData.Scopes.AddRange(scopes);
        authenticationTokenRequestData.Entities.AddRange(entities);

        var authenticationTokenRequestDataEncrypted = _cryptoPayloadProcessor.EncryptData(authenticationTokenRequestData, eaEncryptionPublicKey);

        var request = new GetAuthTokenRsaRequest
        {
            TokenRequestData = authenticationTokenRequestDataEncrypted,
        };

        var callOptions = GetCallOptions(cancellationToken);

        var response = await _enrollmentAuthorityClient.GetAuthTokenRsaAsync(request, callOptions);

        if (response.AuthTokenData == null)
        {
            return new AuthTokens();
        }

        return _cryptoPayloadProcessor.DecryptData<AuthTokens>(response.AuthTokenData, _keyPairs.Value.EncryptionKeyPair);
    }

    private CallOptions GetCallOptions(CancellationToken cancellationToken)
    {
        var headers = new Metadata
        {
            { WellKnownHeaders.XCert, CertificateDataEncoded }
        };
        return new CallOptions(headers: headers, cancellationToken: cancellationToken);
    }

    public async Task<TokenData> RefreshAuthTokenAsync(TokenData refreshToken, CancellationToken cancellationToken = default)
    {
        CheckCertificate();
        if (!_keyPairs.HasValue)
        {
            throw new InvalidOperationException("No certificate nor public keys were imported");
        }

        var eaEncryptionPublicKey = await GetEaEncryptionPublicKeyInternalAsync(cancellationToken);
        var refreshAuthenticationTokenData = new RefreshAuthTokenData
        {
            RefreshToken = refreshToken,
        };

        var refreshAuthenticationTokenDataEncrypted = _cryptoPayloadProcessor.EncryptData(refreshAuthenticationTokenData, eaEncryptionPublicKey);
        var request = new RefreshAuthTokenRsaRequest
        {
            RefreshTokenData = refreshAuthenticationTokenDataEncrypted,
        };

        var response = await _enrollmentAuthorityClient.RefreshAuthTokenRsaAsync(request, GetCallOptions(cancellationToken));

        if (response.AuthTokenData == null)
        {
            return new TokenData();
        }

        return _cryptoPayloadProcessor.DecryptData<TokenData>(response.AuthTokenData, _keyPairs.Value.EncryptionKeyPair);
    }

    public async Task<RegisteredEntitiesData> RegisterEntitiesAsync(EnrollmentEntityDescriptor[] entities, CancellationToken cancellationToken = default)
    {
        CheckCertificate();
        if (!_keyPairs.HasValue)
        {
            throw new InvalidOperationException("No certificate nor public keys were imported");
        }

        var eaEncryptionPublicKey = await GetEaEncryptionPublicKeyInternalAsync(cancellationToken);
        var preparedChallengeData = await PrepareChallengeDataAsync(eaEncryptionPublicKey, _cryptoPayloadProcessor, cancellationToken);
        var registeredEntitiesData = new RegisterEntitiesRequestRsaData
        {
            ChallengeData = preparedChallengeData.ChallengeData,
            Id = preparedChallengeData.ChallengeId.ToString(),
        };
        registeredEntitiesData.Entities.AddRange(entities);

        var registerEntitiesEncrypted = _cryptoPayloadProcessor.EncryptData(registeredEntitiesData, eaEncryptionPublicKey);
        var request = new RegisterEntitiesRsaRequest
        {
            RegisterEntitiesData = registerEntitiesEncrypted,
        };

        var response = await _enrollmentAuthorityClient.RegisterEntitiesRsaAsync(request, GetCallOptions(cancellationToken));

        if (response.RegisteredEntities == null)
        {
            return new RegisteredEntitiesData();
        }

        return _cryptoPayloadProcessor.DecryptData<RegisteredEntitiesData>(response.RegisteredEntities, _keyPairs.Value.EncryptionKeyPair);
    }

    public IDuplexStream<GetEntitiesItemRequest, IGetEntitiesItemResponse> GetEntities(CancellationToken cancellationToken = default)
    {
        CheckCertificate();

        return new GrpcDuplexStreamWrapper<GetEntitiesItemRequest, IGetEntitiesItemResponse, GetEntitiesItemRsaRequest, GetEntitiesItemRsaResponse>(
            _enrollmentAuthorityClient.GetEntitiesRsa(GetCallOptions(cancellationToken)),
            async (r, ct) =>
            {
                if (r.EventVersionInfo != null) // first request
                {
                    var getEntitiesRequest = new GetEntitiesItemRsaRequest
                    {
                        EventVersionInfo = r.EventVersionInfo,
                        RequestId = Guid.NewGuid().ToString(),
                    };

                    // always authorize request with new loop and new stream
                    await AuthorizeEntitiesRequestAsync(getEntitiesRequest, ct);

                    return getEntitiesRequest;
                }

                return new GetEntitiesItemRsaRequest
                {
                    ConfirmedEventVersionInfo = r.ConfirmedEventVersionInfo,
                    RequestId = Guid.NewGuid().ToString(),
                };
            },
            r => r);
    }

    private async Task<GetChallengeDataRsaResponse> GetChallengeDataAsync(CallOptions callOptions)
    {
        var getChallengeData = new GetChallengeDataRsaRequest();

        return await _enrollmentAuthorityClient.GetChallengeDataRsaAsync(getChallengeData, callOptions);
    }

    private async Task<PreparedChallengeData> PrepareChallengeDataAsync(
        EncryptionPublicKeyRsa eaEncryptionPublicKey,
        RsaCryptoPayloadProcessor cryptoPayloadProcessor,
        CancellationToken cancel = default)
    {
        if (!_keyPairs.HasValue)
        {
            throw new InvalidOperationException("No certificate nor public keys were imported");
        }

        var headers = new Metadata
        {
            {WellKnownHeaders.XCert, CertificateDataEncoded}
        };

        var challengeDataResponse = await GetChallengeDataAsync(new CallOptions(headers: headers, cancellationToken: cancel));

        if (challengeDataResponse.EncryptedData == null)
        {
            throw new InvalidOperationException("Could not get challenge data.");
        }

        var preparedChallengeData = cryptoPayloadProcessor.DecryptSignAndEncryptWithOtherKey(challengeDataResponse.EncryptedData, eaEncryptionPublicKey, _keyPairs.Value);
        return new PreparedChallengeData(Guid.Parse(challengeDataResponse.Id), preparedChallengeData);
    }

    private async Task<EncryptionPublicKeyRsa> GetEaEncryptionPublicKeyInternalAsync(CancellationToken cancellationToken = default)
    {
        var request = new GetEncryptionPublicKeyRsaRequest
        {
            AcceptableCiphers = AvailableCiphersRsaEnum.Rsa,
        };

        var eaEncryptionPublicKeyResponse = await _enrollmentAuthorityClient.GetEncryptionPublicKeyRsaAsync(request, new CallOptions(cancellationToken: cancellationToken));

        return new EncryptionPublicKeyRsa
        {
            Key = new EncryptionPublicKeyRsaData
            {
                Rsa = eaEncryptionPublicKeyResponse.EncryptionPublicKey.Key.Rsa,
            },
            EncryptionAlgorithm = eaEncryptionPublicKeyResponse.EncryptionPublicKey.EncryptionAlgorithm
        };
    }

    public async Task<IEnrollIdentityRequest> BuildCertificateSigningRequestAsync(CancellationToken cancellationToken = default)
    {
        if (!_keyPairs.HasValue)
        {
            throw new InvalidOperationException("No certificate nor public keys were imported");
        }

        var encryptionPublicKey = await GetEaEncryptionPublicKeyInternalAsync(cancellationToken);

        var csrBuilder = new RsaCsrBuilder();
        var csr = csrBuilder.BuildCertificateSigningRequest(
            _options.CsrTitle,
            _options.EnrollmentIdentity,
            _options.Entities,
            _keyPairs.Value);

        var encryptedData = _cryptoPayloadProcessor.SignAndEncryptWithOtherKey(csr, encryptionPublicKey, _keyPairs.Value.VerificationKeyPair);
        var enrollIdentity = new EnrollIdentityRsaRequest
        {
            Id = _options.EnrollmentIdentity!.Id.ToString(),
            CsrEncryptedData = encryptedData,
        };
        return new RsaEnrollIdentityRequest
        {
            Request = enrollIdentity
        };
    }

    public async Task<IRefreshEnrolledIdentityRequest> BuildRefreshEnrolledIdentityRequestAsync(CryptographyKeys refreshKeys, CancellationToken cancellationToken = default)
    {
        var rsaRefreshKeys = ToRsaCryptographyKeys(refreshKeys);
        var encryptionPublicKey = await GetEaEncryptionPublicKeyInternalAsync(cancellationToken);
        var preparedChallengeData = await PrepareChallengeDataAsync(encryptionPublicKey, _cryptoPayloadProcessor, cancellationToken);
        var csrBuilder = new RsaCsrBuilder();
        var refreshCsr = csrBuilder.BuildCertificateSigningRequest(
            _options.CsrTitle,
            _options.EnrollmentIdentity,
            _options.Entities,
            rsaRefreshKeys);
        var refreshCsrSigned = _cryptoPayloadProcessor.Sign(refreshCsr, rsaRefreshKeys.VerificationKeyPair);
        var refreshEncryptedData = new RefreshEncryptedRsaData
        {
            ChallengeData = preparedChallengeData.ChallengeData,
            Id = preparedChallengeData.ChallengeId.ToString(),
            SignedCsrData = refreshCsrSigned,
        };
        var refreshEncryptedDataEncrypted = _cryptoPayloadProcessor.EncryptData(refreshEncryptedData, encryptionPublicKey);
        var refreshEnrollmentIdentityRequest = new RefreshEnrolledIdentityRsaRequest
        {
            RefreshEncryptedData = refreshEncryptedDataEncrypted,
            Id = refreshCsr.Data.Id,
        };
        
        return new RsaRefreshEnrolledIdentityRequest
        {
            Request = refreshEnrollmentIdentityRequest
        };
    }

    public async Task<CertificateData> RefreshEnrolledIdentityAsync(IRefreshEnrolledIdentityRequest request,
        CancellationToken cancellationToken = default)
    {
        if (request is not RsaRefreshEnrolledIdentityRequest rsaRequest)
        {
            throw new NotSupportedException("This implementation supports only RSA requests.");
        }

        var response = await _enrollmentAuthorityClient.RefreshEnrolledIdentityRsaAsync(rsaRequest.Request, GetCallOptions(cancellationToken));
        
        return response.IssuedCertificate;
    }

    public async Task ConfirmEnrolledIdentityAsync(CertificateData newCertificate, CancellationToken cancellationToken = default)
    {
        var eaEncryptionPublicKey = await GetEaEncryptionPublicKeyInternalAsync(cancellationToken);
        var preparedChallengeData = await PrepareChallengeDataAsync(eaEncryptionPublicKey, _cryptoPayloadProcessor, cancellationToken);
        var confirmedRequestRsaData = new ConfirmedRequestRsaData
        {
            Id = preparedChallengeData.ChallengeId.ToString(),
            ChallengeData = preparedChallengeData.ChallengeData,
            XNewCert = newCertificate.Data,
        };
        var confirmedRequestRsaDataEncrypted = _cryptoPayloadProcessor.EncryptData(confirmedRequestRsaData, eaEncryptionPublicKey);
        var request = new ConfirmEnrolledIdentityRsaRequest
        {
            ConfirmRequestData = confirmedRequestRsaDataEncrypted,
        };
        await _enrollmentAuthorityClient.ConfirmEnrolledIdentityRsaAsync(request, GetCallOptions(cancellationToken));
    }

    private async Task AuthorizeEntitiesRequestAsync(GetEntitiesItemRsaRequest request, CancellationToken cancel)
    {
        var eaEncryptionPublicKey = await GetEaEncryptionPublicKeyInternalAsync(cancel);
        var preparedChallengeData = await PrepareChallengeDataAsync(eaEncryptionPublicKey, _cryptoPayloadProcessor, cancel);
        request.ChallengeData = preparedChallengeData.ChallengeData;
        request.Id = preparedChallengeData.ChallengeId.ToString();
    }

    private static RsaCryptographyKeys ToRsaCryptographyKeys(CryptographyKeys keyPairs)
    {
        if (keyPairs.EncryptionKeyPair is not IRsaEncryptionKeyPairHandle encryptionKeyPair)
        {
            throw new NotSupportedException("This implementation supports only RSA encryption key pairs.");
        }

        if (keyPairs.VerificationKeyPair is not IRsaVerificationKeyPairHandle verificationKeyPair)
        {
            throw new NotSupportedException("This implementation supports only RSA verification key pairs.");
        }

        var rsaKeyPairs = new RsaCryptographyKeys(encryptionKeyPair, verificationKeyPair);
        
        return rsaKeyPairs;
    }

    private record PreparedChallengeData(Guid ChallengeId, EncryptedRsaData ChallengeData);
}