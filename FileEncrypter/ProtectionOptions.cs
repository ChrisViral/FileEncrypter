using System.Security.Cryptography;

namespace FileEncrypter;

/// <summary>
/// Protection options
/// </summary>
/// <param name="Password">The password to protect the files with</param>
/// <param name="EncryptedExtension">The encrypted file extension</param>
/// <param name="ValidModes">Type of protections to allow applying</param>
/// <param name="SearchPattern">Search pattern when protecting folders (supports wildcards)</param>
/// <param name="SearchOption">Whether to include subdirectories when protecting folders"</param>
/// <param name="Scope">Protection scope for the files</param>
/// <param name="Compression">The type of file compression to use</param>
/// <param name="DeleteFiles">If old files should be kept deleted after being processed</param>
/// <param name="FileTimeout">The timeout for individual file encryption/decryption, in ms (-1 for no timeout)</param>
public readonly record struct ProtectionOptions(byte[]? Password = null,
                                                string EncryptedExtension = ProtectionOptions.DEFAULT_EXTENSION,
                                                ProtectionModes ValidModes = ProtectionModes.All,
                                                string SearchPattern = ProtectionOptions.DEFAULT_PATTERN,
                                                SearchOption SearchOption = SearchOption.TopDirectoryOnly,
                                                DataProtectionScope Scope = DataProtectionScope.CurrentUser,
                                                CompressionOption Compression = CompressionOption.Brotli,
                                                bool DeleteFiles = true,
                                                int FileTimeout = -1)
{
    /// <summary>
    /// Default encrypted extension
    /// </summary>
    public const string DEFAULT_EXTENSION = ".enc";

    /// <summary>
    /// Default search pattern
    /// </summary>
    public const string DEFAULT_PATTERN = "*";

    /// <summary>
    /// Creates new ProtectionOptions with default values
    /// </summary>
    public ProtectionOptions() : this(null) { }
}
