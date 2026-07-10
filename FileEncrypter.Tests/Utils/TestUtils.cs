using System.Security.Cryptography;
using System.Text;
using FileEncrypter.Collections;

namespace FileEncrypter.Tests.Utils;

public static class TestUtils
{
    public const string FILE_EXTENSION = ".txt";
    public const string FILE_NAME = $"testdata{FILE_EXTENSION}";
    public const string FILE_DATA = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. "
                                  + "Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. "
                                  + "Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. "
                                  + "Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";
    public const string PASSWORD  = "password123";
    public const string ENCRYPTED_FILE_NAME = FILE_NAME + ProtectionOptions.DEFAULT_EXTENSION;

    public static byte[] FileDataBytes { get; } = Encoding.UTF8.GetBytes(FILE_DATA);

    public static byte[] PasswordBytes { get; } = Encoding.UTF8.GetBytes(PASSWORD);
}
