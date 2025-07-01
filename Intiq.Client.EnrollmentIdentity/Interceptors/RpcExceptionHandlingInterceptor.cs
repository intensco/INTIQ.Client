using System.Threading;
using System.Threading.Tasks;
using Grpc.Core;
using Grpc.Core.Interceptors;
using Intiq.Client.EnrollmentIdentity.Exceptions;

namespace Intiq.Client.EnrollmentIdentity.Interceptors;

public class RpcExceptionHandlingInterceptor : Interceptor
{
    public override TResponse BlockingUnaryCall<TRequest, TResponse>(
        TRequest request,
        ClientInterceptorContext<TRequest, TResponse> context,
        BlockingUnaryCallContinuation<TRequest, TResponse> continuation)
    {
        try
        {
            return continuation(request, context);
        }
        catch (RpcException e) when (e.StatusCode == StatusCode.Unauthenticated)
        {
            throw new InvalidCertificateException();
        }
    }

    public override AsyncUnaryCall<TResponse> AsyncUnaryCall<TRequest, TResponse>(
        TRequest request,
        ClientInterceptorContext<TRequest, TResponse> context,
        AsyncUnaryCallContinuation<TRequest, TResponse> continuation)
    {
        var call = continuation(request, context);

        return new AsyncUnaryCall<TResponse>(
            HandleExceptions(call.ResponseAsync),
            call.ResponseHeadersAsync,
            call.GetStatus,
            call.GetTrailers,
            call.Dispose);
    }

    private static async Task<T> HandleExceptions<T>(Task<T> inner)
    {
        try
        {
            return await inner;
        }
        catch (RpcException e) when (e.StatusCode == StatusCode.Unauthenticated)
        {
            throw new InvalidCertificateException();
        }
    }

    public override AsyncServerStreamingCall<TResponse> AsyncServerStreamingCall<TRequest, TResponse>(
            TRequest request,
            ClientInterceptorContext<TRequest, TResponse> context,
            AsyncServerStreamingCallContinuation<TRequest, TResponse> continuation)
    {
        var call = continuation(request, context);

        return new AsyncServerStreamingCall<TResponse>(
            HandleExceptions(call.ResponseStream),
            call.ResponseHeadersAsync,
            call.GetStatus,
            call.GetTrailers,
            call.Dispose);
    }

    private IAsyncStreamReader<TResponse> HandleExceptions<TResponse>(IAsyncStreamReader<TResponse> responseStream) 
        where TResponse : class
    {
        return new AsyncStreamReaderWrapper<TResponse>(responseStream);
    }

    public override AsyncClientStreamingCall<TRequest, TResponse> AsyncClientStreamingCall<TRequest, TResponse>(
        ClientInterceptorContext<TRequest, TResponse> context,
        AsyncClientStreamingCallContinuation<TRequest, TResponse> continuation)
    {
        var call = continuation(context);

        return new AsyncClientStreamingCall<TRequest, TResponse>(
            HandleExceptions(call.RequestStream),
            HandleExceptions(call.ResponseAsync),
            call.ResponseHeadersAsync,
            call.GetStatus,
            call.GetTrailers,
            call.Dispose);
    }

    private IClientStreamWriter<TRequest> HandleExceptions<TRequest>(IClientStreamWriter<TRequest> requestStream)
    {
        return new ClientStreamWriterWrapper<TRequest>(requestStream);
    }

    public override AsyncDuplexStreamingCall<TRequest, TResponse> AsyncDuplexStreamingCall<TRequest, TResponse>(
        ClientInterceptorContext<TRequest, TResponse> context,
        AsyncDuplexStreamingCallContinuation<TRequest, TResponse> continuation)
    {
        var call = continuation(context);

        return new AsyncDuplexStreamingCall<TRequest, TResponse>(
            HandleExceptions(call.RequestStream),
            HandleExceptions(call.ResponseStream),
            call.ResponseHeadersAsync,
            call.GetStatus,
            call.GetTrailers,
            call.Dispose);
    }

    private class AsyncStreamReaderWrapper<TResponse> : IAsyncStreamReader<TResponse>
    {
        private readonly IAsyncStreamReader<TResponse> _innerReader;

        public TResponse Current => _innerReader.Current;

        public AsyncStreamReaderWrapper(IAsyncStreamReader<TResponse> innerReader)
        {
            _innerReader = innerReader;
        }
        
        public async Task<bool> MoveNext(CancellationToken cancellationToken)
        {
            return await HandleExceptions(_innerReader.MoveNext(cancellationToken));
        }
    }

    private class AsyncStreamWriterWrapper<TResponse> : IAsyncStreamWriter<TResponse>
    {
        private readonly IAsyncStreamWriter<TResponse> _innerWriter;

        public WriteOptions? WriteOptions
        {
            get => _innerWriter.WriteOptions;
            set => _innerWriter.WriteOptions = value;
        }

        public AsyncStreamWriterWrapper(IAsyncStreamWriter<TResponse> innerWriter)
        {
            _innerWriter = innerWriter;
        }

        public async Task WriteAsync(TResponse message)
        {
            async Task<bool> GetTask()
            {
                await _innerWriter.WriteAsync(message);
                return true;
            }

            await HandleExceptions(GetTask());
        }

        public async Task WriteAsync(TResponse message, CancellationToken cancellationToken)
        {
            async Task<bool> GetTask()
            {
                await _innerWriter.WriteAsync(message, cancellationToken);
                return true;
            }

            await HandleExceptions(GetTask());
        }
    }

    private class ClientStreamWriterWrapper<TRequest> : AsyncStreamWriterWrapper<TRequest>, IClientStreamWriter<TRequest>
    {
        private readonly IClientStreamWriter<TRequest> _innerWriter;

        public ClientStreamWriterWrapper(IClientStreamWriter<TRequest> innerWriter) 
            : base(innerWriter)
        {
            _innerWriter = innerWriter;
        }

        public async Task CompleteAsync()
        {
            async Task<bool> GetTask()
            {
                await _innerWriter.CompleteAsync();
                return true;
            }

            await HandleExceptions(GetTask());
        }
    }
}
