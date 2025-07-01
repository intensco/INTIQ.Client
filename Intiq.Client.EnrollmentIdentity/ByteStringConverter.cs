using System;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using Google.Protobuf;

namespace Intiq.Client.EnrollmentIdentity;

public class ByteStringConverter : JsonConverter<ByteString>
{
    public override ByteString? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var bytes = JsonSerializer.Deserialize<byte[]>(ref reader, options);

        return bytes == null 
            ? null 
            : ByteString.CopyFrom(bytes.ToArray());
    }

    public override void Write(Utf8JsonWriter writer, ByteString value, JsonSerializerOptions options)
    {
        JsonSerializer.Serialize(writer, value.ToByteArray(), options);
    }
}