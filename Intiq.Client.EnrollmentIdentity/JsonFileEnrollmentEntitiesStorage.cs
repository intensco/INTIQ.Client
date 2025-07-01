using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Intiq.Client.EnrollmentIdentity.Configuration;
using Intiq.SystemGateways.EnrollmentAuthority.Common.V2;
using Microsoft.Extensions.Options;

namespace Intiq.Client.EnrollmentIdentity;

public class JsonFileEnrollmentEntitiesStorage : IEnrollmentEntitiesStorage
{
    private readonly EnrollmentStorageOptions _options;

    private class EntitiesModel
    {
        public long? OutboxPosition { get; set; }
        public Dictionary<string, EnrollEntityStatusEnum> StatusesByEntityId { get; set; } = new();
    }

    public JsonFileEnrollmentEntitiesStorage(IOptions<EnrollmentStorageOptions> options)
    {
        _options = options.Value;
    }

    public async Task StoreEntityStatusesAsync(
        IEnumerable<(string entityId, EnrollEntityStatusEnum status)> statuses,
        long outboxPosition, 
        string enrollmentIdentityId, 
        CancellationToken cancellationToken = default)
    {
        var (_,statusesByEntityId) = await GetEntityStatusesAsync(enrollmentIdentityId, cancellationToken);
        var storageModel = new EntitiesModel
        {
            OutboxPosition = outboxPosition, // outbox position is overwritten
            StatusesByEntityId = statusesByEntityId // last known entity statuses are kept
        };

        foreach(var (entityId, status) in statuses) // new entity statuses overwrite those already stored
        {
            storageModel.StatusesByEntityId[entityId] = status;
        }

        var json = JsonSerializer.Serialize(storageModel);
        var certificateFileName = string.Format(_options.EntityStatusesFileJsonNamePattern, enrollmentIdentityId);
        var tempCertificateFileName = FormattableString.Invariant($"{certificateFileName}.tmp");

        Directory.CreateDirectory(Path.GetDirectoryName(certificateFileName)!);

        await File.WriteAllTextAsync(tempCertificateFileName, json, cancellationToken);
        File.Move(tempCertificateFileName, certificateFileName, overwrite: true);
    }

    public async Task<(long? outboxPosition, Dictionary<string, EnrollEntityStatusEnum> statusesByEntityId)> GetEntityStatusesAsync(
        string enrollmentIdentityId,
        CancellationToken cancellationToken = default)
    {
        var keyPairFileName = string.Format(_options.EntityStatusesFileJsonNamePattern, enrollmentIdentityId);

        if (!File.Exists(keyPairFileName))
        {
            return (null, new());
        }

        var json = await File.ReadAllTextAsync(keyPairFileName, cancellationToken);

        if (string.IsNullOrWhiteSpace(json))
        {
            return (null, new());
        }

        var storageModel = JsonSerializer.Deserialize<EntitiesModel?>(json);
        if (storageModel == null)
        {
            return (null, new());
        }

        return (storageModel.OutboxPosition, storageModel.StatusesByEntityId);
    }
}