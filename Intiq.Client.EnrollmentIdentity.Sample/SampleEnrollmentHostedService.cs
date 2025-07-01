using Intiq.SystemGateways.EnrollmentAuthority.Common.V2;
using Microsoft.Extensions.Hosting;

namespace Intiq.Client.EnrollmentIdentity.Sample;

public class SampleEnrollmentHostedService : IHostedService
{
    private readonly IEnrollmentProcessor _enrollmentProcessor;

    public SampleEnrollmentHostedService(IEnrollmentProcessor enrollmentProcessor)
    {
        _enrollmentProcessor = enrollmentProcessor;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        Console.WriteLine("Enrolling identity...");
        await _enrollmentProcessor.EnsureIdentityIsEnrolledAsync(cancellationToken);

        var sampleEntity = CreateSampleEntity();
        var sampleEntityId = sampleEntity.Id;

        Console.WriteLine("Registering additional entities...");
        await _enrollmentProcessor.RegisterEntitiesAsync([sampleEntity], cancellationToken);

        await foreach (var statusChanges in _enrollmentProcessor.WatchEntityStatusesAsync(cancellationToken))
        {
            if (statusChanges.Any(x => x.entityId == sampleEntityId && x.status == EnrollEntityStatusEnum.Active))
            {
                var accessToken = await _enrollmentProcessor.GetEntityBearerTokenAsync(sampleEntityId, cancellationToken);

                Console.WriteLine($"Received access token: {Environment.NewLine} {accessToken}");
            }
        }
    }

    private static EnrollmentEntityDescriptor CreateSampleEntity()
    {
        var additionalEntityId = Guid.NewGuid().ToString();

        return new()
        {
            Id = additionalEntityId, // this place accepts any string, pair (identityId, entityId) is unique in the system
            AliasId = "Alias" + additionalEntityId,
            Category = "Category",
            Title = "Title" + additionalEntityId,
            Description = "Description" + additionalEntityId,
            Type = EnrollmentEntityTypeEnum.Device,
        };
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
    }
}