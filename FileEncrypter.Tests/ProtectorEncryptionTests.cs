using System.Text;
using CSharpFunctionalExtensions;
using FileEncrypter.Tests.Utils;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;

namespace FileEncrypter.Tests;

public class ProtectorEncryptionTests
{
    [Fact]
    public async Task EncryptDecrypt_RoundTrip_DefaultOptions_ShouldMatchOriginal()
    {
        // Arrange
        using TempDirectory tempDir = new();
        const string FILE_NAME = "sample.txt";
        string originalFilePath = Path.Combine(tempDir.DirectoryPath, FILE_NAME);
        byte[] originalBytes = "Hello World!"u8.ToArray();
        await File.WriteAllBytesAsync(originalFilePath, originalBytes);

        ProtectionOptions options = new(); // defaults: DeleteFiles=true
        Protector protector = new(NullLogger<Protector>.Instance, options);

        // Act – encrypt
        Result resultEncrypt = await protector.ProtectAll(new[] { new FileInfo(originalFilePath) });

        // Assert encryption success
        resultEncrypt.IsSuccess.Should().BeTrue();

        string encryptedPath = originalFilePath + options.EncryptedExtension;
        File.Exists(encryptedPath).Should().BeTrue();
        File.Exists(originalFilePath).Should().BeFalse(); // deleted after encryption

        // Act – decrypt
        Result resultDecrypt = await protector.ProtectAll(new[] { new FileInfo(encryptedPath) });

        // Assert decryption success and original restored
        resultDecrypt.IsSuccess.Should().BeTrue();

        File.Exists(originalFilePath).Should().BeTrue();
        File.Exists(encryptedPath).Should().BeFalse(); // removed after decryption

        byte[] decryptedBytes = await File.ReadAllBytesAsync(originalFilePath);
        decryptedBytes.Should().Equal(originalBytes);
    }

    [Fact]
    public async Task EncryptDecrypt_RoundTrip_WithCustomPassword_ShouldSucceedAndFailWithWrongPassword()
    {
        // Arrange
        using TempDirectory tempDir = new();
        const string FILE_NAME = "sample.txt";
        string originalFilePath = Path.Combine(tempDir.DirectoryPath, FILE_NAME);
        byte[] originalBytes = "Sensitive data"u8.ToArray();
        await File.WriteAllBytesAsync(originalFilePath, originalBytes);

        const string CORRECT_PASSWORD = "secret123";
        const string WRONG_PASSWORD = "wrongpass";

        ProtectionOptions optionsCorrect = new(Password: Encoding.UTF8.GetBytes(CORRECT_PASSWORD));
        Protector protectorEncrypt = new(NullLogger<Protector>.Instance, optionsCorrect);

        // Act – encrypt
        Result resultEncrypt = await protectorEncrypt.ProtectAll(new[] { new FileInfo(originalFilePath) });
        resultEncrypt.IsSuccess.Should().BeTrue();

        string encryptedPath = originalFilePath + optionsCorrect.EncryptedExtension;
        File.Exists(encryptedPath).Should().BeTrue();
        File.Exists(originalFilePath).Should().BeFalse(); // deleted

        // Attempt decryption with wrong password
        ProtectionOptions optionsWrong = new(Password: Encoding.UTF8.GetBytes(WRONG_PASSWORD));
        Protector protectorDecryptWrong = new(NullLogger<Protector>.Instance, optionsWrong);

        Result resultWrong = await protectorDecryptWrong.ProtectAll(new[] { new FileInfo(encryptedPath) });
        resultWrong.IsFailure.Should().BeTrue();
        // Encrypted file should still exist
        File.Exists(encryptedPath).Should().BeTrue();

        // Decrypt with correct password
        Protector protectorDecryptCorrect = new(NullLogger<Protector>.Instance, optionsCorrect);
        Result resultCorrect = await protectorDecryptCorrect.ProtectAll(new[] { new FileInfo(encryptedPath) });
        resultCorrect.IsSuccess.Should().BeTrue();

        // Encrypted file should be removed after successful decryption
        File.Exists(encryptedPath).Should().BeFalse();
        File.Exists(originalFilePath).Should().BeTrue();

        byte[] decryptedBytes = await File.ReadAllBytesAsync(originalFilePath);
        decryptedBytes.Should().Equal(originalBytes);
    }

    [Fact]
    public async Task EncryptFile_EmptyContent_ShouldHandleGracefully()
    {
        // Arrange – create empty file
        using TempDirectory tempDir = new();
        const string FILE_NAME = "empty.txt";
        string emptyPath = Path.Combine(tempDir.DirectoryPath, FILE_NAME);
        await File.WriteAllBytesAsync(emptyPath, []);

        ProtectionOptions options = new(); // default
        Protector protector = new(NullLogger<Protector>.Instance, options);

        // Act – encrypt
        Result resultEncrypt = await protector.ProtectAll(new[] { new FileInfo(emptyPath) });
        resultEncrypt.IsSuccess.Should().BeTrue();

        string encryptedPath = emptyPath + options.EncryptedExtension;
        File.Exists(encryptedPath).Should().BeTrue();
        File.Exists(emptyPath).Should().BeFalse(); // original removed

        // Act – decrypt
        Result resultDecrypt = await protector.ProtectAll(new[] { new FileInfo(encryptedPath) });
        resultDecrypt.IsSuccess.Should().BeTrue();

        File.Exists(emptyPath).Should().BeTrue();
        File.Exists(encryptedPath).Should().BeFalse();

        byte[] decryptedBytes = await File.ReadAllBytesAsync(emptyPath);
        decryptedBytes.Length.Should().Be(0);
    }

    [Fact]
    public async Task DecryptFile_WhenEncryptedExtensionMismatch_ShouldFailGracefully()
    {
        // Arrange – create a file that has the encrypted extension but is not actually encrypted
        using TempDirectory tempDir = new();
        const string FILE_NAME = "corrupt.enc";
        string corruptPath = Path.Combine(tempDir.DirectoryPath, FILE_NAME);
        await File.WriteAllBytesAsync(corruptPath, "Not encrypted data"u8.ToArray());

        // Only encryption allowed – decryption disabled
        ProtectionOptions options = new(ValidModes: ProtectionModes.Encrypt);

        Protector protector = new(NullLogger<Protector>.Instance, options);

        // Act – attempt to protect the .enc file (which would trigger a decrypt path)
        Result result = await protector.ProtectAll(new[] { new FileInfo(corruptPath) });

        // Assert
        result.IsFailure.Should().BeTrue();
        File.Exists(corruptPath).Should().BeTrue(); // original should not be deleted
    }
}
