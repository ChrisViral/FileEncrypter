namespace FileEncrypter;

public readonly record struct ProtectionOptions(byte[]? Password = null,
                                                ProtectionModes ValidModes = ProtectionModes.All,
                                                string SearchPattern = "*",
                                                SearchOption SearchOption = SearchOption.TopDirectoryOnly,
                                                int FileTimeout = 1000);
