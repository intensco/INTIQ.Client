using System;
using Intiq.Client.EnrollmentIdentity.Configuration;
using Intiq.Client.EnrollmentIdentity.Cryptography;
using Intiq.Client.EnrollmentIdentity.Cryptography.Native;
using Intiq.Client.EnrollmentIdentity.Encryption;
using Intiq.Client.EnrollmentIdentity.Encryption.EC;
using Intiq.Client.EnrollmentIdentity.Encryption.RSA;
using Microsoft.Extensions.DependencyInjection;

namespace Intiq.Client.EnrollmentIdentity.Extensions;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddEnrollmentIdentity(this IServiceCollection services, EnrollmentEncryptionType enrollmentEncryptionType)
    {
        services.AddOptions<EnrollmentOptions>().BindConfiguration("Enrollment");

        switch (enrollmentEncryptionType)
        {
            case EnrollmentEncryptionType.Rsa:
                services.AddTransient<IEnrollmentEncryptionHandler, RsaEnrollmentEncryptionHandler>();
                services.AddTransient<RsaCryptoPayloadProcessor>();
                services.AddTransient<IRsaSignaturePrimitives, NativeRsaSignaturePrimitives>();
                services.AddTransient<IRsaEncryptionPrimitives, NativeRsaEncryptionPrimitives>();
                services.AddTransient<IKeyPairGenerator, RsaKeyPairGenerator>();
                break;
            case EnrollmentEncryptionType.Ec:
                services.AddTransient<IEnrollmentEncryptionHandler, EcEnrollmentEncryptionHandler>();
                services.AddTransient<EcCryptoPayloadProcessor>();
                services.AddTransient<IEcSignaturePrimitives, NativeEcSignaturePrimitives>();
                services.AddTransient<IEcEncryptionPrimitives, NativeEcEncryptionPrimitives>();
                services.AddTransient<IKeyPairGenerator, EcKeyPairGenerator>();
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(enrollmentEncryptionType), enrollmentEncryptionType, null);
        }

        services.AddSingleton<IEnrollmentIdentity, EnrollmentIdentity>();
        services.AddSingleton<IEnrollmentProcessor, EnrollmentProcessor>();

        return services;
    }

    public static IServiceCollection AddEnrollmentIdentityFileStorage(this IServiceCollection services)
    {
        services.AddOptions<EnrollmentStorageOptions>().BindConfiguration("EnrollmentStorage");

        services.AddTransient<IEnrollmentIdentityStorage, JsonFileEnrollmentIdentityStorage>();
        services.AddTransient<IEnrollmentEntitiesStorage, JsonFileEnrollmentEntitiesStorage>();

        return services;
    }

    public static IServiceCollection AddEnrollmentIdentityMemoryStorage(this IServiceCollection services)
    {
        services.AddTransient<IEnrollmentIdentityStorage, MemoryEnrollmentIdentityStorage>();
        services.AddTransient<IEnrollmentEntitiesStorage, MemoryEnrollmentEntitiesStorage>();

        return services;
    }
}