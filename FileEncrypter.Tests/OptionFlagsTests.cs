using CSharpFunctionalExtensions;
using FileEncrypter.Tests.Utils;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;

namespace FileEncrypter.Tests;

public class OptionFlagsTests
{
    [Fact]
    public async Task ValidModes_EncryptOnly_ShouldPreventDecryption()
    {
        using TempDirectory tempDir = new();
        const string FILE_NAME = "data.txt";
        string filePath = Path.Combine(tempDir.DirectoryPath, FILE_NAME);
        await File.WriteAllBytesAsync(filePath, "secret"u8.ToArray());

        // Only encryption allowed
        ProtectionOptions options = new(ValidModes: ProtectionModes.Encrypt);
        Protector protector = new(NullLogger<Protector>.Instance, options);

        // Encrypt – should succeed
        Result encResult = await protector.ProtectAll(new[] { new FileInfo(filePath) });
        encResult.IsSuccess.Should().BeTrue();
        string encryptedPath = filePath + options.EncryptedExtension;
        File.Exists(encryptedPath).Should().BeTrue();
        File.Exists(filePath).Should().BeFalse();

        // Decrypt – should fail because mode disallows decrypt
        Protector protectorDecrypt = new(NullLogger<Protector>.Instance, options);
        Result decResult = await protectorDecrypt.ProtectAll(new[] { new FileInfo(encryptedPath) });
        decResult.IsFailure.Should().BeTrue();
        File.Exists(encryptedPath).Should().BeTrue(); // still present
    }

    [Fact]
    public async Task ValidModes_DecryptOnly_ShouldPreventEncryption()
    {
        // Start with an encrypted file (simulated by raw bytes)
        using TempDirectory tempDir = new();
        string tempFilePath = Path.Combine(tempDir.DirectoryPath, "cipher.txt");
        await File.WriteAllBytesAsync(tempFilePath, "topsecret"u8.ToArray());

        // Only encryption allowed – no decryption mode
        ProtectionOptions encryptOptions = new(ValidModes: ProtectionModes.Encrypt, DeleteFiles: false);
        Protector protectorEncrypt = new(NullLogger<Protector>.Instance, encryptOptions);

        // Encrypt should succeed
        Result encResult = await protectorEncrypt.ProtectFile(new FileInfo(tempFilePath), CancellationToken.None);
        encResult.IsSuccess.Should().BeTrue();

        // Only decryption allowed – no encryption mode
        string tempEncryptedPath = tempFilePath + encryptOptions.EncryptedExtension;
        ProtectionOptions decryptOptions = new(ValidModes: ProtectionModes.Decrypt, DeleteFiles: false);
        Protector protectorDecrypt = new(NullLogger<Protector>.Instance, decryptOptions);

        // Decrypt should succeed
        Result decResult = await protectorDecrypt.ProtectAll(new[] { new FileInfo(tempEncryptedPath) });
        decResult.IsSuccess.Should().BeTrue();

        // Encrypting with the protector only meant for encrypting should fail
        encResult = await protectorDecrypt.ProtectAll(new[] { new FileInfo(tempFilePath) });
        encResult.IsFailure.Should().BeTrue();

        // Encrypting with the protector only meant for encrypting should fail
        decResult = await protectorEncrypt.ProtectAll(new[] { new FileInfo(tempEncryptedPath) });
        decResult.IsFailure.Should().BeTrue();
    }

    [Fact]
    public async Task EncryptedExtension_CustomSuffix_ShouldUseGivenExtension()
    {
        using TempDirectory tempDir = new();
        const string FILE_NAME = "plain.txt";
        string filePath = Path.Combine(tempDir.DirectoryPath, FILE_NAME);
        await File.WriteAllBytesAsync(filePath, "content"u8.ToArray());

        const string CUSTOM_EXT = ".crypt";
        ProtectionOptions options = new(EncryptedExtension: CUSTOM_EXT);
        Protector protector = new(NullLogger<Protector>.Instance, options);

        // Encrypt – should use the custom suffix
        Result encResult = await protector.ProtectAll(new[] { new FileInfo(filePath) });
        encResult.IsSuccess.Should().BeTrue();
        string expectedEncrypted = filePath + CUSTOM_EXT;
        File.Exists(expectedEncrypted).Should().BeTrue();
    }

    [Fact]
    public async Task DeleteFiles_True_ShouldRemoveOriginal_OnEncryptAndDecrypt()
    {
        // Create a plain file and encrypt it with default options (DeleteFiles=true)
        using TempDirectory tempDir = new();
        const string FILE_NAME = "sample.txt";
        string filePath = Path.Combine(tempDir.DirectoryPath, FILE_NAME);
        await File.WriteAllBytesAsync(filePath, "data"u8.ToArray());

        ProtectionOptions options = new(); // DeleteFiles defaults to true
        Protector protector = new(NullLogger<Protector>.Instance, options);

        Result encResult = await protector.ProtectAll(new[] { new FileInfo(filePath) });
        encResult.IsSuccess.Should().BeTrue();

        string encryptedPath = filePath + options.EncryptedExtension;
        File.Exists(encryptedPath).Should().BeTrue();
        File.Exists(filePath).Should().BeFalse(); // original removed

        // Decrypt back – delete flag should again remove the .enc file
        Protector protectorDecrypt = new(NullLogger<Protector>.Instance, options);
        Result decResult = await protectorDecrypt.ProtectAll(new[] { new FileInfo(encryptedPath) });
        decResult.IsSuccess.Should().BeTrue();

        File.Exists(filePath).Should().BeTrue();
        File.Exists(encryptedPath).Should().BeFalse();
    }

    [Fact]
    public async Task DeleteFiles_False_ShouldRetainBothVersions()
    {
        using TempDirectory tempDir = new();
        const string FILE_NAME = "original.txt";
        string filePath = Path.Combine(tempDir.DirectoryPath, FILE_NAME);
        await File.WriteAllBytesAsync(filePath, "keep it"u8.ToArray());

        ProtectionOptions options = new(DeleteFiles: false); // keep originals
        Protector protector = new(NullLogger<Protector>.Instance, options);

        Result encResult = await protector.ProtectAll(new[] { new FileInfo(filePath) });
        encResult.IsSuccess.Should().BeTrue();

        string encryptedPath = filePath + options.EncryptedExtension;
        File.Exists(encryptedPath).Should().BeTrue();
        File.Exists(filePath).Should().BeTrue(); // original stays
    }
}
