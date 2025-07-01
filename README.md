# INTIQ.Client

Welcome to the INTIQ.Client repository, where you'll find sample implementations of clients along with the necessary guidelines that enable you to integrate with INTIQ's ecosystem.

>**DISCLAIMER**: This code is provided solely for informational and educational purposes and is not intended for production use. Delivered 'as is', it carries no expressed or implied warranties. The author and publisher are not responsible or liable for any errors, omissions, damages, or losses incurred through the use or reliance on this code. Use this code at your own risk.

- [INTIQ.Client](#intiqclient)
  - [Protos](#protos)
  - [Enrollment Identity Client](#enrollment-identity-client)
    - [Add Dependencies to ServiceCollection](#add-dependencies-to-servicecollection)
      - [Specify Encryption Type](#specify-encryption-type)
      - [Utilize File Storage](#utilize-file-storage)
      - [Register INTIQ Service gRPC Client](#register-intiq-service-grpc-client)
    - [Implement Enrollment](#implement-enrollment)
      - [Enroll Your Identity](#enroll-your-identity)
      - [Register Entities](#register-entities)
      - [Get Access Token](#get-access-token)
        - [Token for a Single Entity](#token-for-a-single-entity)
        - [Token(s) for Entities in Buckets](#tokens-for-entities-in-buckets)
    - [HSM Integration](#hsm-integration)
      - [Elliptic Curve Cryptography (ECC)](#elliptic-curve-cryptography-ecc)
        - [IEcSignaturePrimitives](#iecsignatureprimitives)
        - [IEcEncryptionPrimitives](#iecencryptionprimitives)
        - [IEcVerificationKeyPairHandle](#iecverificationkeypairhandle)
        - [IEcEncryptionKeyPairHandle](#iecencryptionkeypairhandle)
      - [RSA](#rsa)
## Protos
INTIQ.Client depends on INTIQ Device Gateway Proto files that you should have received from INTIQ Platform administrator based on version installed. Unzip and copy all files to "Protos" directory to initialize INTIQ.Client with provided version of API contract.

**Required Protos directory structure is**

```
- Protos
    |- intiq
        |- api
        |- shared
        |- system_gateways
        |- ...
```

> **Please note** that content of `Protos/intiq/*` directory depends on features that are available for you to achieve goal. This client requires `system_gateways/enrollment_authority/*` and `shared/common/*` directories as a minimum Proto scope.

## Enrollment Identity Client

This section provides instructions for setting up the Enrollment Identity client.

>**TIP**: Find the Enrollment Identity client code in the `Intiq.Client.EnrollmentIdentity` project, including a usage example in the `Intiq.Client.EnrollmentIdentity.Sample` project.

### Add Dependencies to ServiceCollection

We'll start by setting up the Enrollment Identity services, taking the following actions to configure the ServiceCollection appropriately:

#### Specify Encryption Type

``` cs
services.AddEnrollmentIdentity(enrollmentEncryptionType);
```

Assign the corresponding value to the `enrollmentEncryptionType` variable:

- `EnrollmentEncryptionType.Rsa` for RSA encryption
- `EnrollmentEncryptionType.Ec` for Elliptic Curve encryption (ECC)

#### Utilize File Storage

``` cs
services.AddEnrollmentIdentityFileStorage();
```

><span style="color:red;">**WARNING**: This sample implementation is provided solely for informational and educational purposes and is not intended for production use. Delivered 'as is', it should be employed for development, testing, and experimentation. If you consider to use it in a production environment, it might be necessary to implement additional security protection layers that align with the requirements of the system you are integrating with. Moreover, we strongly recommend that you integrate a Hardware Security Module (HSM) to comply with today's security standards, as detailed in the [HSM Integration](#hsm-integration) section.</span>

#### Register INTIQ Service gRPC Client

``` cs
services.AddSingleton(_ => {
    var grpcChannel = GrpcChannel.ForAddress("[url_of_intiq_should_be_placed_here]");
    grpcChannel.Intercept(new RpcExceptionHandlingInterceptor());
    return new EnrollmentAuthorityService.EnrollmentAuthorityServiceClient(grpcChannel);
});
```

### Implement Enrollment

Here you'll find a reference implementation using the `SampleEnrollmentHostedService` class, showcasing our preferred enrollment method through a clear call chain.

#### Enroll Your Identity

To enroll your identity, run the `IEnrollmentProcessor.EnsureIdentityIsEnrolledAsync` method. This checks the storage provider for existing data. If none is found, it creates and stores the necessary data.

>**NOTE:** The method finishes when your Enrollment Identity receives approval from the system. The approval can be immediate or await manual confirmation from an admin user, depending on the system configuration. You can safely recall the method if the application terminates during the waiting period.

#### Register Entities

Upon receiving the approval response, your enrollment identity is successfully enrolled in the system. Now you can register entities by executing:

``` cs
await _enrollmentProcessor.RegisterEntitiesAsync(entities, cancellationToken);
```

>**NOTE**: Execute the registration method multiple times if needed – it's safe, even with the same entities.

#### Wait for Entity Approval

After entity registration, you must wait for approval (`Active` status) from the server side by executing:

```
await foreach (var statusChanges in _enrollmentProcessor.WatchEntityStatusesAsync(cancellationToken))
{
    if (statusChanges.Any(x => x.entityId == [your_entity_id] && x.status == EnrollEntityStatusEnum.Active))
    {
        // now your entity is successfully approved
    }
}
```
>**NOTE**: Entity status can be updated (e.g. disabling the entity by system admin) during application run. You should handle these status changes, e.g. close communication channels made on behalf of the entity.

#### Get Access Token

To obtain access tokens for specific entities, use the corresponding method for either individual entities or groups of entities (buckets). This grants you entity-specific access token(s), with each token acting as the bearer token for your subsequent interactions with the system on behalf of the associated entity or bucket.

##### Token for a Single Entity

If you are sure entity is approved (has status `Active`) from the server side, call:

``` cs
string accessToken = await _enrollmentProcessor.GetEntityBearerTokenAsync(entityId, cancellationToken);
```
>**NOTE**: It throws an `UnauthorizedEntityException` when entity is not `Active` at the time.

or call:

``` cs
string accessToken = await _enrollmentProcessor.TryGetEntityBearerTokenAsync(entityId, cancellationToken);
```

>**NOTE**: It returns null when entity is not `Active`.

##### Token(s) for Entities in Buckets

>**NOTE**: A single token supports up to 50 entities. The method automatically organizes entities into buckets if exceeding this limit.

``` cs
IDictionary<string[], string> accessTokensPerBucket = await _enrollmentProcessor.GetEntityBearerTokensPerBucketAsync(entityIds, cancellationToken);
```

>**NOTE**: The method returns a dictionary where each key represents a bucket of entities, and the corresponding value is the access token associated with that bucket. Only `Active` entities are returned.

### HSM Integration

For secure encryption in production scenarios, it might be **required** to implement a Hardware Security Module (HSM) integration. The default encryption sample included in this code utilizes an in-memory implementation, making it neither persistent nor secure. This sample implementation is intended solely for educational purposes.

>**NOTE**: In HSM, keys are securely stored and typically accessed by integer index.

Enrollment supports both RSA and Elliptic Curve Cryptography (ECC), allowing you to choose between ECC or RSA with just one implementation.

#### Elliptic Curve Cryptography (ECC)

To enable HSM for ECC, implement the following interfaces:

- `IEcSignaturePrimitives`: Interface for ECC digital signatures
- `IEcEncryptionPrimitives`: Interface for ECC encryption and decryption
- `IEcVerificationKeyPairHandle`: Interface for handling ECC verification key pairs
- `IEcEncryptionKeyPairHandle`: Interface for handling ECC encryption key pairs

##### IEcSignaturePrimitives

``` cs
public class HsmEcSignaturePrimitives : IEcSignaturePrimitives
{
    public IEcVerificationKeyPairHandle GenerateKeyPair()
    {
        // create key pair using HSM API; HSM should return an index of the key in HSM and an instance of HsmEcVerificationKeyPairHandle
    }

    public IEcVerificationKeyPairHandle DeserializeKeyPair(byte[] serializedKeyPair)
    {
        // deserialize content to HsmEcVerificationKeyPairHandle and perform any necessary steps to prepare the key in HSM at the specified index for use
    }

    public bool Verify(SignedEcData signedData)
    {
        // verify the signed data using only public information; this method can be implemented with NativeEcSignaturePrimitives or, for improved performance, delegated to the HSM processor
    }

    public SignedEcData Sign(PlainTextData plainText, SupportedVerificationAlgorithms algorithm,
        IEcVerificationKeyPairHandle verificationKeyPair)
    {
        if (verificationKeyPair is not HsmEcVerificationKeyPairHandle nativeKeyPairHandle)
            throw new NotSupportedException($"Implementation supports only {nameof(HsmEcVerificationKeyPairHandle)}");

        int hsmKeyIndex = nativeKeyPairHandle.HsmKeyIndex;
        // call the HSM API to sign plain text data using the specified hsmKeyIndex
    }
}
```

##### IEcEncryptionPrimitives

``` cs
public class HsmEcEncryptionPrimitives : IEcEncryptionPrimitives
{
    public IEcEncryptionKeyPairHandle GenerateKeyPair()
    {
        // create a key pair using the HSM API; the HSM should return an index of the key in the HSM and an instance of HsmEcEncryptionKeyPairHandle
    }

    public IEcEncryptionKeyPairHandle DeserializeKeyPair(byte[] serializedKeyPair)
    {
        // deserialize the content to an HsmEcEncryptionKeyPairHandle instance and performs any necessary steps to prepare the key in the HSM at the specified index for use
    }

    public PlainTextData Decrypt(EncryptedEcData encryptedData, IEcEncryptionKeyPairHandle encryptionKeyPair)
    {
        if (encryptionKeyPair is not HsmEcEncryptionKeyPairHandle nativeKeyPairHandle)
            throw new NotSupportedException($"Implementation supports only {nameof(HsmEcEncryptionKeyPairHandle)}");

        int hsmKeyIndex = nativeKeyPairHandle.HsmKeyIndex;
        // perform ECDH basic agreement calculation in the HSM using hsmKeyIndex
        // the remaining part of the key derivation function can be implemented, drawing inspiration from NativeEcEncryptionPrimitives
    }

    public EncryptedEcData Encrypt(PlainTextData plainTextData, EcEncryptionPublicKey encryptionPublicKey)
    {
        // utilize only public information; can be implemented using NativeEcEncryptionPrimitives or, for performance reasons, delegated to the HSM processor
    }
}
```

##### IEcVerificationKeyPairHandle

``` cs
public class HsmEcVerificationKeyPairHandle : IEcVerificationKeyPairHandle
{
    private readonly EcVerificationPublicKey _verificationPublicKeyEc;

    public int HsmKeyIndex { get; }

    public HsmEcVerificationKeyPairHandle(EcVerificationPublicKey verificationPublicKeyEc, int hsmKeyIndex)
    {
        _verificationPublicKeyEc = verificationPublicKeyEc;
        HsmKeyIndex = hsmKeyIndex;
    }

    public byte[] Serialize()
    {
        // serialize HSM index and VerificationPublicKeyEc
    }

    public EcVerificationPublicKey GetVerificationPublicKey()
    {
        return _verificationPublicKeyEc;
    }
}
```

##### IEcEncryptionKeyPairHandle

``` cs
public class HsmEcEncryptionKeyPairHandle : IEcEncryptionKeyPairHandle
{
    private readonly EcEncryptionPublicKey _encryptionPublicKeyEc;

    public int HsmKeyIndex { get; }

    public HsmEcEncryptionKeyPairHandle(EcEncryptionPublicKey encryptionPublicKeyEc, int hsmKeyIndex)
    {
        _encryptionPublicKeyEc = encryptionPublicKeyEc;
        HsmKeyIndex = hsmKeyIndex;
    }

    public byte[] Serialize()
    {
        // serialize HSM index and EncryptionPublicKeyEc
    }

    public EcEncryptionPublicKey GetEncryptionPublicKey()
    {
        return _encryptionPublicKeyEc;
    }

    public static HsmEcEncryptionKeyPairHandle Deserialize(byte[] serializedKeyPair)
    {
        // return a deserialized instance
    }
}
```

#### RSA

The RSA implementation is similar to the [ECC implementation](#elliptic-curve-cryptography-ecc), except it uses the following interfaces:

- `IRsaSignaturePrimitives`: Interface for RSA digital signatures
- `IRsaEncryptionPrimitives`: Interface for RSA encryption and decryption
- `IRsaVerificationKeyPairHandle`: Interface for handling RSA verification key pairs
- `IRsaEncryptionKeyPairHandle`: Interface for handling RSA encryption key pairs