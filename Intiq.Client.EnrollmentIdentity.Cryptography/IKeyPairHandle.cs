namespace Intiq.Client.EnrollmentIdentity.Cryptography;

/// <summary>
/// Handle for key pair. This can represent a key pair in memory or a reference to a key pair in HSM.
/// </summary>
public interface IKeyPairHandle
{
    /// <summary>
    /// Serializes the key pair handle to be stored in the storage.
    /// For example native implementation serialize the whole key pair to be stored in a common storage
    /// while HSM implementation can store an index to the key pair in the storage.
    /// </summary>
    /// <returns>Byte array representation of the key pair to be stored</returns>
    byte[] Serialize();
}