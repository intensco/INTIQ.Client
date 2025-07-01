namespace Intiq.Client.EnrollmentIdentity.Configuration;

public class EnrollmentStorageOptions
{
    public string KeyPairJsonFileNamePattern { get; set; } = "enrollment/{0}/cryptography_keys.json";
    public string CsrFileJsonNamePattern { get; set; } = "enrollment/{0}/csr.json";
    public string CertificateFileJsonNamePattern { get; set; } = "enrollment/{0}/certificate.json";
    public string PendingCertificateFileJsonNamePattern { get; set; } = "enrollment/{0}/pending_certificate.json";
    public string EntityStatusesFileJsonNamePattern { get; set; } = "enrollment/{0}/entity_statuses.json";
}