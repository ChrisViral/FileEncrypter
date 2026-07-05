namespace FileEncrypter;

/// <summary>
/// File compression option
/// </summary>
public enum CompressionOption : byte
{
    None,
    Brotli,
    Deflate,
    GZip,
    ZLib
}
