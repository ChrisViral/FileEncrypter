namespace FileEncrypter;

[Flags]
public enum ProtectionModes
{
    None    = 0b00,
    Encrypt = 0b01,
    Decrypt = 0b10,
    All     = 0b11
}

public static class ProtectionModesExtensions
{
    extension(ProtectionModes value)
    {
        public bool HasFlagFast(ProtectionModes flag) => (value & flag) is not 0;
    }
}
