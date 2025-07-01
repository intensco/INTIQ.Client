using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Intiq.Client.EnrollmentIdentity;

public interface IDuplexStream<in TRequest, out TResponse> : IDisposable
{
    Task WriteAsync(TRequest request, CancellationToken cancellationToken = default);
    IAsyncEnumerable<TResponse> ReadAllAsync(CancellationToken cancellationToken = default);
}