namespace Intiq.Client.EnrollmentIdentity;

public record OutboxEntity(SystemGateways.EnrollmentAuthority.Common.V2.EnrollmentEntity Entity, long OutboxPosition);