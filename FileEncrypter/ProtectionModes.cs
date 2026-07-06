using JetBrains.Annotations;

namespace FileEncrypter;

/// <summary>
/// File protection modes
/// </summary>
[Flags, PublicAPI]
public enum ProtectionModes
{
    /// <summary>No encryption or decryption allowed</summary>
    None    = 0b00,
    /// <summary>Only encryption allowed</summary>
    Encrypt = 0b01,
    /// <summary>Only decryption allowed</summary>
    Decrypt = 0b10,
    /// <summary>Both encryption and decryption allowed</summary>
    All     = 0b11
}

/// <summary>
/// ProtectionModes extensions
/// </summary>
public static class ProtectionModesExtensions
{
    /// <summary>
    /// ProtectionModes extensions
    /// </summary>
    /// <param name="value">Current ProtectionModes value</param>
    extension(ProtectionModes value)
    {
        /// <summary>
        /// If the specified flag is set on these ProtectionModes
        /// </summary>
        /// <param name="flag">Flag to check</param>
        /// <returns><see langword="true"/> if the flag is set, otherwiuse <see langword="false"/></returns>
        public bool HasFlagFast(ProtectionModes flag) => (value & flag) is not 0;
    }
}
