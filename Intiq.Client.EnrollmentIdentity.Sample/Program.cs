using Grpc.Core.Interceptors;
using Grpc.Net.Client;
using Intiq.Client.EnrollmentIdentity.Configuration;
using Intiq.Client.EnrollmentIdentity.Extensions;
using Intiq.Client.EnrollmentIdentity.Interceptors;
using Intiq.SystemGateways.EnrollmentAuthority.Authority.V2;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Intiq.Client.EnrollmentIdentity.Sample;

public class Program
{
    public static async Task Main(string[] args)
    {
        await Host
            .CreateDefaultBuilder(args)
            .ConfigureServices((context, services) =>
            {
                var enrollmentOptions = new EnrollmentOptions();
                context.Configuration.Bind("Enrollment", enrollmentOptions);

                services.AddEnrollmentIdentity(enrollmentOptions.EnrollmentEncryptionType);

                services.AddEnrollmentIdentityFileStorage();

                services.AddSingleton(_ => CreateEnrollmentAuthorityServiceClient());

                services.AddHostedService<SampleEnrollmentHostedService>();
            })
            .Build()
            .RunAsync();
    }

    private static EnrollmentAuthorityService.EnrollmentAuthorityServiceClient CreateEnrollmentAuthorityServiceClient()
    {
        var httpHandler = new HttpClientHandler();
        
        // don't use in production scenarios, certificates should be verified
        httpHandler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;

        var grpcChannel = GrpcChannel.ForAddress("[url_of_intiq_should_be_placed_here]", new GrpcChannelOptions { HttpHandler = httpHandler });
        
        grpcChannel.Intercept(new RpcExceptionHandlingInterceptor());

        return new EnrollmentAuthorityService.EnrollmentAuthorityServiceClient(grpcChannel);
    }
}