using System.Collections.Generic;

namespace Intiq.Client.EnrollmentIdentity;

public class KeyHolder
{
    public string Key { get; set; } = default!;
    public List<string> EntityIds { get; set; } = new();
}