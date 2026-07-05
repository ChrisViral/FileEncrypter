using System;
using JetBrains.Annotations;

namespace FileEncrypter;

/// <summary>
/// File protection modes
/// </summary>
[Flags, PublicAPI]
public enum ProtectionModes
{
    None    = 0b00,
    Encrypt = 0b01,
    Decrypt = 0b10,
    All     = 0b11
}

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
