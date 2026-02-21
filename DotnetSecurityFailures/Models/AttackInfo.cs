namespace DotnetSecurityFailures.Models;

/// <summary>
/// Represents a single attack payload example
/// </summary>
public class AttackPayload
{
    public string Name { get; set; } = string.Empty;
    public string Code { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Severity { get; set; } = string.Empty;
}

/// <summary>
/// Universal class for predefined attack examples
/// Uses Input/Input2 for maximum flexibility
/// </summary>
public class PredefinedAttack
{
    /// <summary>
    /// Primary input value - can be string, int, or any other type
    /// </summary>
    public object Input { get; set; } = string.Empty;
    
    /// <summary>
    /// Secondary input - for attacks requiring two separate values
    /// </summary>
    public object? Input2 { get; set; }
    
    public string Description { get; set; } = string.Empty;
    public string Label { get; set; } = string.Empty;

    // Helper methods for safe type conversion
    public string GetInputAsString() => Input?.ToString() ?? string.Empty;
    public int GetInputAsInt() => Input is int i ? i : 0;
    public string GetInput2AsString() => Input2?.ToString() ?? string.Empty;
}
