using System.Security.Cryptography;
using FluentAssertions;
using System.IO.Abstractions.TestingHelpers;
using CSharpFunctionalExtensions;
using Microsoft.Extensions.Logging.Abstractions;

namespace FileEncrypter.Tests;

public class IntegrationTests
{
    private readonly MockFileSystem _fileSystem;
    private const string TEST_DIR = @"C:\TestData";

    public IntegrationTests()
    {
        // Use a mocked filesystem for predictable tests without side effects
        this._fileSystem = new MockFileSystem();
        this._fileSystem.Directory.CreateDirectory(TEST_DIR);
    }

    [Fact]
    public async Task ProtectAll_ShouldProcessFilesCorrectly()
    {
        // Arrange
        string tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tempDir);
        try
        {
            List<string> files = [Path.Combine(tempDir, "file1.txt"), Path.Combine(tempDir, "subdir", "file2.txt")];
            await File.WriteAllTextAsync(files[0], "Content of file 1");
            Directory.CreateDirectory(Path.GetDirectoryName(files[1])!);
            await File.WriteAllTextAsync(files[1], "Content of file 2");

            ProtectionOptions options = new()
            {
                Password = "password"u8.ToArray(),
                Scope = DataProtectionScope.CurrentUser,
                EncryptedExtension = ".enc",
                Compression = CompressionOption.GZip,
                ValidModes = ProtectionModes.All,
                DeleteFiles = true
            };

            Protector protector = new(NullLogger<Protector>.Instance, options);
            var targets = files.Select(f => new FileInfo(f)).ToArray();

            // Act
            Result result = await protector.ProtectAll(targets);

            // Assert
            result.IsSuccess.Should().BeTrue();

            // Check if encrypted files exist and originals are deleted
            File.Exists(files[0] + ".enc").Should().BeTrue();
            File.Exists(files[0]).Should().BeFalse();

            File.Exists(files[1] + ".enc").Should().BeTrue();
            File.Exists(files[1]).Should().BeFalse();
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, true);
        }
    }

    [Fact]
    public async Task EndToEnd_EncryptAndDecrypt_ShouldBeIdentical()
    {
        // Arrange
        string tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tempDir);
        try
        {
            string filePath = Path.Combine(tempDir, "secret.txt");
            string originalContent = "This is a secret message that must remain hidden.";
            await File.WriteAllTextAsync(filePath, originalContent);

            ProtectionOptions options = new()
            {
                Password = "securepassword"u8.ToArray(),
                Scope = DataProtectionScope.CurrentUser,
                EncryptedExtension = ".enc",
                Compression = CompressionOption.Brotli,
                ValidModes = ProtectionModes.All,
                DeleteFiles = true
            };

            Protector protector = new(NullLogger<Protector>.Instance, options);

            // Act - Protect
            Result protectResult = await protector.ProtectFile(new FileInfo(filePath), CancellationToken.None);
            protectResult.IsSuccess.Should().BeTrue();

            string encryptedPath = filePath + ".enc";
            File.Exists(encryptedPath).Should().BeTrue();
            File.Exists(filePath).Should().BeFalse(); // DeleteFiles = true

            // Act - Unprotect
            // Since we need to pass the data buffer as well, we read it into a PooledArray/buffer first
            // or simply use the high-level logic if DecryptFile was intended to be helper.
            // Actually, Protector.DecryptFile(FileInfo file, PooledArray<byte> data, ...)
            // takes 'data' which is the encrypted content of 'file'.

            using PooledArray<byte> encryptedData = new((int)new FileInfo(encryptedPath).Length);
            await using (FileStream fs = File.OpenRead(encryptedPath))
            using (MemoryStream ms = new(encryptedData.AsRawArray))
            {
                fs.CopyTo(ms, encryptedData.Length);
            }

            // Re-creating the file at the original path for DecryptFile to "save" to is tricky
            // because it's deleted. Let's assume we want to decrypt into a specific target.
            // However, DecryptFile as written saves to Path.ChangeExtension(file.FullName, null).

            Result decryptResult = await protector.DecryptFile(new FileInfo(encryptedPath), encryptedData, CancellationToken.None);
            decryptResult.IsSuccess.Should().BeTrue();

            string decryptedContent = await File.ReadAllTextAsync(filePath);

            // Assert
            decryptedContent.Should().Be(originalContent);
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, true);
        }
    }

    [Fact]
    public async Task ProtectAll_WithInvalidPassword_ShouldFailDecryption()
    {
        // Arrange
        string tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tempDir);
        try
        {
            string filePath = Path.Combine(tempDir, "secret.txt");
            await File.WriteAllTextAsync(filePath, "Some data");

            ProtectionOptions options1 = new()
            {
                Password = "correctpassword"u8.ToArray(),
                Scope = DataProtectionScope.CurrentUser,
                EncryptedExtension = ".enc",
                Compression = CompressionOption.Deflate,
                ValidModes = ProtectionModes.All
            };
            Protector protector1 = new(NullLogger<Protector>.Instance, options1);

            await protector1.ProtectFile(new FileInfo(filePath), CancellationToken.None);
            string encryptedPath = filePath + ".enc";

            // Act - Try with wrong password
            ProtectionOptions options2 = new()
            {
                Password = "wrongpassword"u8.ToArray(),
                Scope = DataProtectionScope.CurrentUser,
                EncryptedExtension = ".enc",
                Compression = CompressionOption.Deflate,
                ValidModes = ProtectionModes.All
            };
            Protector protector2 = new(NullLogger<Protector>.Instance, options2);

            using PooledArray<byte> encryptedData = new((int)new FileInfo(encryptedPath).Length);
            await using (FileStream fs = File.OpenRead(encryptedPath))
            using (MemoryStream ms = new(encryptedData.AsRawArray))
            {
                fs.CopyTo(ms, encryptedData.Length);
            }

            Result decryptResult = await protector2.DecryptFile(new FileInfo(encryptedPath), encryptedData, CancellationToken.None);

            // Assert
            decryptResult.IsFailure.Should().BeTrue();
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, true);
        }
    }

    [Fact]
    public async Task ProtectAll_CorruptedFile_ShouldReturnFailure()
    {
        // Arrange
        string tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tempDir);
        try
        {
            string filePath = Path.Combine(tempDir, "corrupt.enc");
            // Write random bytes that are not a valid encrypted/compressed header
            await File.WriteAllBytesAsync(filePath, [0xFF, 0x00, 0xDE, 0xAD, 0xBE, 0xEF]);

            ProtectionOptions options = new()
            {
                Password = "password"u8.ToArray(),
                Scope = DataProtectionScope.CurrentUser,
                EncryptedExtension = ".enc",
                Compression = CompressionOption.GZip,
                ValidModes = ProtectionModes.All
            };
            Protector protector = new(NullLogger<Protector>.Instance, options);

            // Act & Assert
            using PooledArray<byte> corruptedData = new((int)new FileInfo(filePath).Length);
            await using (FileStream fs = File.OpenRead(filePath))
            using (MemoryStream ms = new(corruptedData.AsRawArray))
            {
                fs.CopyTo(ms, corruptedData.Length);
            }

            Result result = await protector.DecryptFile(new FileInfo(filePath), corruptedData, CancellationToken.None);
            result.IsFailure.Should().BeTrue();
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, true);
        }
    }
}
