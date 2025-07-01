using System;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using System.Threading;
using System.Threading.Tasks;
using Intiq.Client.EnrollmentIdentity.Configuration;
using Intiq.Client.EnrollmentIdentity.Encryption;
using Intiq.SystemGateways.EnrollmentAuthority.Authority.V2;
using Microsoft.Extensions.Options;

namespace Intiq.Client.EnrollmentIdentity;

public class JsonFileEnrollmentIdentityStorage : IEnrollmentIdentityStorage
{
    private readonly EnrollmentStorageOptions _options;
    private readonly IKeyPairGenerator _keyPairGenerator;

    private class CsrRequestTypeResolver : DefaultJsonTypeInfoResolver
    {
        public override JsonTypeInfo GetTypeInfo(Type type, JsonSerializerOptions options)
        {
            var jsonTypeInfo = base.GetTypeInfo(type, options);

            if (jsonTypeInfo.Type == typeof(IEnrollIdentityRequest))
            {
                jsonTypeInfo.PolymorphismOptions = new JsonPolymorphismOptions
                {
                    DerivedTypes =
                    {                       
                        new JsonDerivedType(typeof(RsaEnrollIdentityRequest), nameof(RsaEnrollIdentityRequest)),
                        new JsonDerivedType(typeof(EcEnrollIdentityRequest), nameof(EcEnrollIdentityRequest))
                    }
                };
            }

            return jsonTypeInfo;
        }
    }

    private record CryptographyKeysStorageModel(byte[] EncryptionKeyPair, byte[] VerificationKeyPair);

    private record PendingCertificateStorageModel(CertificateData Certificate, CryptographyKeysStorageModel Keys);

    private static readonly JsonSerializerOptions JsonSerializerOptions = new()
    {
        Converters =
        {
            new ByteStringConverter()
        },
        TypeInfoResolver = new CsrRequestTypeResolver()
    };

    public JsonFileEnrollmentIdentityStorage(IOptions<EnrollmentStorageOptions> options, IKeyPairGenerator keyPairGenerator)
    {
        _keyPairGenerator = keyPairGenerator;
        _options = options.Value;
    }

    public async Task StoreKeyPairsAsync(CryptographyKeys cryptographyKeys, Guid enrollmentIdentityId, CancellationToken cancellationToken = default)
    {
        var encryptionKeyPair = cryptographyKeys.EncryptionKeyPair.Serialize();
        var verificationKeyPair = cryptographyKeys.VerificationKeyPair.Serialize();
        var storageModel = new CryptographyKeysStorageModel(encryptionKeyPair, verificationKeyPair);
        var json = JsonSerializer.Serialize(storageModel, JsonSerializerOptions);

        var keyPairFileName = string.Format(_options.KeyPairJsonFileNamePattern, enrollmentIdentityId);
        var tempKeyPairFileName = FormattableString.Invariant($"{keyPairFileName}.tmp");
        Directory.CreateDirectory(Path.GetDirectoryName(keyPairFileName)!);
        await File.WriteAllTextAsync(tempKeyPairFileName, json, cancellationToken);
        File.Move(tempKeyPairFileName, keyPairFileName, overwrite: true);
    }

    public async Task<CryptographyKeys?> TryGetKeyPairsAsync(Guid enrollmentIdentityId, CancellationToken cancellationToken = default)
    {
        var keyPairFileName = string.Format(_options.KeyPairJsonFileNamePattern, enrollmentIdentityId);

        if (!File.Exists(keyPairFileName))
        {
            return null;
        }

        var json = await File.ReadAllTextAsync(keyPairFileName, cancellationToken);

        if (string.IsNullOrWhiteSpace(json))
        {
            return null;
        }

        var storageModel = JsonSerializer.Deserialize<CryptographyKeysStorageModel?>(json, JsonSerializerOptions);
        if (storageModel == null)
        {
            return null;
        }

        return _keyPairGenerator.DeserializeKeyPairs(storageModel.EncryptionKeyPair, storageModel.VerificationKeyPair);
    }

    public async Task StoreCertificateAsync(CertificateData certificate, Guid enrollmentIdentityId, CancellationToken cancellationToken = default)
    {
        var json = JsonSerializer.Serialize(certificate, JsonSerializerOptions);
        var certificateFileName = string.Format(_options.CertificateFileJsonNamePattern, enrollmentIdentityId);
        var tempCertificateFileName = FormattableString.Invariant($"{certificateFileName}.tmp");

        Directory.CreateDirectory(Path.GetDirectoryName(certificateFileName)!);

        await File.WriteAllTextAsync(tempCertificateFileName, json, cancellationToken);
        File.Move(tempCertificateFileName, certificateFileName, overwrite: true);
    }

    public async Task<CertificateData?> TryGetCertificateAsync(Guid enrollmentIdentityId, CancellationToken cancellationToken = default)
    {
        var certificateFileName = string.Format(_options.CertificateFileJsonNamePattern, enrollmentIdentityId);

        if (!File.Exists(certificateFileName))
        {
            return null;
        }

        var json = await File.ReadAllTextAsync(certificateFileName, cancellationToken);

        if (string.IsNullOrWhiteSpace(json))
        {
            return null;
        }

        return JsonSerializer.Deserialize<CertificateData?>(json, JsonSerializerOptions);
    }

    public async Task StoreCertificateSigningRequestAsync(IEnrollIdentityRequest certificateSigningRequest, Guid enrollmentIdentityId, CancellationToken cancellationToken = default)
    {
        var json = JsonSerializer.Serialize(certificateSigningRequest, JsonSerializerOptions);
        var csrPairFileName = string.Format(_options.CsrFileJsonNamePattern, enrollmentIdentityId);
        var tempCsrPairFileName = FormattableString.Invariant($"{csrPairFileName}.tmp");

        Directory.CreateDirectory(Path.GetDirectoryName(csrPairFileName)!);

        await File.WriteAllTextAsync(tempCsrPairFileName, json, cancellationToken);
        File.Move(tempCsrPairFileName, csrPairFileName, overwrite: true);
    }

    public async Task<IEnrollIdentityRequest?> TryGetCertificateSigningRequestAsync(Guid enrollmentIdentityId, CancellationToken cancellationToken = default)
    {
        var csrPairFileName = string.Format(_options.CsrFileJsonNamePattern, enrollmentIdentityId);

        if (!File.Exists(csrPairFileName))
        {
            return null;
        }

        var json = await File.ReadAllTextAsync(csrPairFileName, cancellationToken);

        return string.IsNullOrWhiteSpace(json) 
            ? null 
            : JsonSerializer.Deserialize<IEnrollIdentityRequest>(json, JsonSerializerOptions);
    }

    public async Task StorePendingCertificateAsync(CertificateData certificate, CryptographyKeys keys, Guid enrollmentIdentityId, CancellationToken cancellationToken = default)
    {
        var storageModel = new PendingCertificateStorageModel(certificate, new CryptographyKeysStorageModel(keys.EncryptionKeyPair.Serialize(), keys.VerificationKeyPair.Serialize()));
        var json = JsonSerializer.Serialize(storageModel, JsonSerializerOptions);
        var pendingCertificateFileName = string.Format(_options.PendingCertificateFileJsonNamePattern, enrollmentIdentityId);
        var tempPendingCertificateFileName = FormattableString.Invariant($"{pendingCertificateFileName}.tmp");

        Directory.CreateDirectory(Path.GetDirectoryName(pendingCertificateFileName)!);
        await File.WriteAllTextAsync(tempPendingCertificateFileName, json, cancellationToken);
        File.Move(tempPendingCertificateFileName, pendingCertificateFileName, overwrite: true);
    }

    public async Task ConfirmPendingCertificateAsync(Guid enrollmentIdentityId, CancellationToken cancellationToken = default)
    {
        var pendingCertificateFileName = string.Format(_options.PendingCertificateFileJsonNamePattern, enrollmentIdentityId);

        if (!File.Exists(pendingCertificateFileName))
        {
            return;
        }

        var json = await File.ReadAllTextAsync(pendingCertificateFileName, cancellationToken);

        if (string.IsNullOrWhiteSpace(json))
        {
            return;
        }

        var storageModel = JsonSerializer.Deserialize<PendingCertificateStorageModel?>(json, JsonSerializerOptions);
        if (storageModel == null)
        {
            File.Delete(pendingCertificateFileName);
            return;
        }
            
        await StoreCertificateAsync(storageModel.Certificate, enrollmentIdentityId, cancellationToken);
        var keys = _keyPairGenerator.DeserializeKeyPairs(storageModel.Keys.EncryptionKeyPair, storageModel.Keys.VerificationKeyPair);
        await StoreKeyPairsAsync(keys, enrollmentIdentityId, cancellationToken);
        File.Delete(pendingCertificateFileName);
    }

    public async Task<(CertificateData PendingCertificate, CryptographyKeys Keys)?> TryGetPendingCertificateAsync(Guid enrollmentIdentityId, CancellationToken cancellationToken = default)
    {
        var pendingCertificateFileName = string.Format(_options.PendingCertificateFileJsonNamePattern, enrollmentIdentityId);

        if (!File.Exists(pendingCertificateFileName))
        {
            return null;
        }

        var json = await File.ReadAllTextAsync(pendingCertificateFileName, cancellationToken);

        if (string.IsNullOrWhiteSpace(json))
        {
            return null;
        }

        var storageModel = JsonSerializer.Deserialize<PendingCertificateStorageModel?>(json, JsonSerializerOptions);
        if (storageModel == null)
        {
            return null;
        }

        var keys = _keyPairGenerator.DeserializeKeyPairs(storageModel.Keys.EncryptionKeyPair, storageModel.Keys.VerificationKeyPair);
        return (storageModel.Certificate, keys);
    }
}