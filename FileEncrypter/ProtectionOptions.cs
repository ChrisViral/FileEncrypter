using System.Security.Cryptography;

namespace FileEncrypter;

public readonly record struct ProtectionOptions(byte[]? Password = null,
                                                ProtectionModes ValidModes = ProtectionModes.All,
                                                string SearchPattern = "*",
                                                SearchOption SearchOption = SearchOption.TopDirectoryOnly,
                                                DataProtectionScope Scope = DataProtectionScope.CurrentUser,
                                                bool Compress = true,
                                                int FileTimeout = -1);
