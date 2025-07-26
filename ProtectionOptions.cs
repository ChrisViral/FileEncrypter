namespace FileEncrypter;

public readonly record struct ProtectionOptions(byte[]? Password, ProtectionModes ValidModes, string SearchPattern, SearchOption SearchOption);
