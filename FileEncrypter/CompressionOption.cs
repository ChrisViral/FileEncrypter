namespace FileEncrypter;

/// <summary>
/// File compression option
/// </summary>
public enum CompressionOption : byte
{
    /// <summary>No compression</summary>
    None,
    /// <summary>Brotli compression</summary>
    Brotli,
    /// <summary>Deflate compression</summary>
    Deflate,
    /// <summary>GZip compression</summary>
    GZip,
    /// <summary>ZLib compression</summary>
    ZLib
}
