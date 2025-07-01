using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using Grpc.Core;

namespace Intiq.Client.EnrollmentIdentity;

public class GrpcDuplexStreamWrapper<TRequest, TResponse, TInnerRequest, TInnerResponse> : IDuplexStream<TRequest, TResponse>
{
    private readonly AsyncDuplexStreamingCall<TInnerRequest, TInnerResponse> _call;
    private readonly Func<TRequest, CancellationToken, Task<TInnerRequest>> _requestMapper;
    private readonly Func<TInnerResponse, TResponse> _responseMapper;

    public GrpcDuplexStreamWrapper(
        AsyncDuplexStreamingCall<TInnerRequest, TInnerResponse> call,
        Func<TRequest, CancellationToken, Task<TInnerRequest>> requestMapper,
        Func<TInnerResponse, TResponse> responseMapper)
    {
        _call = call;
        _requestMapper = requestMapper;
        _responseMapper = responseMapper;
    }

    public async Task WriteAsync(TRequest request, CancellationToken cancellationToken = default)
    {
        await _call.RequestStream.WriteAsync(await _requestMapper(request, cancellationToken), cancellationToken);
    }

    public async IAsyncEnumerable<TResponse> ReadAllAsync([EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        await foreach (var response in _call.ResponseStream.ReadAllAsync(cancellationToken))
        {
            yield return _responseMapper(response);
        }
    }

    public void Dispose()
    {
        _call.Dispose();
    }
}