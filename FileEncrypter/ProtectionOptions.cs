using System.Security.Cryptography;

namespace FileEncrypter;

/// <summary>
/// Protection options
/// </summary>
/// <param name="Password">The password to protect the files with</param>
/// <param name="ValidModes">Type of protections to allow applying</param>
/// <param name="SearchPattern">Search pattern when protecting folders (supports wildcards)</param>
/// <param name="SearchOption">Whether to include subdirectories when protecting folders"</param>
/// <param name="Scope">Protection scope for the files</param>
/// <param name="Compress">If files should be compressed before encryption</param>
/// <param name="DeleteFiles">If old files should be kept deleted after being processed</param>
/// <param name="FileTimeout">The timeout for individual file encryption/decryption, in ms (-1 for no timeout)</param>
public readonly record struct ProtectionOptions(byte[]? Password = null,
                                                ProtectionModes ValidModes = ProtectionModes.All,
                                                string SearchPattern = "*",
                                                SearchOption SearchOption = SearchOption.TopDirectoryOnly,
                                                DataProtectionScope Scope = DataProtectionScope.CurrentUser,
                                                bool Compress = true,
                                                bool DeleteFiles = true,
                                                int FileTimeout = -1);
