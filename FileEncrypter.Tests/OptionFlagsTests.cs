using CSharpFunctionalExtensions;
using FileEncrypter.Tests.Utils;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;

namespace FileEncrypter.Tests;

public sealed class OptionFlagsTests : IDisposable
{
    private readonly TempDirectory tempDirectory = new();

    [Fact]
    public async Task ValidModes_EncryptOnly_ShouldPreventDecryption()
    {
        // Setup data
        await File.WriteAllBytesAsync(this.tempDirectory.OriginalPath, TestUtils.FileDataBytes);

        // Only encryption allowed
        ProtectionOptions options = new(ValidModes: ProtectionModes.Encrypt);
        Protector protector = new(NullLogger<Protector>.Instance, options);

        // Encrypt should succeed
        Result encryptResult = await protector.ProtectFile(this.tempDirectory.OriginalFile, CancellationToken.None);
        encryptResult.IsSuccess.Should().BeTrue();
        File.Exists(this.tempDirectory.EncryptedPath).Should().BeTrue();
        File.Exists(this.tempDirectory.OriginalPath).Should().BeFalse();

        // Decrypt should fail
        Result decryptResult = await protector.ProtectFile(this.tempDirectory.EncryptedFile, CancellationToken.None);
        decryptResult.IsFailure.Should().BeTrue();
        File.Exists(this.tempDirectory.EncryptedPath).Should().BeTrue();
        File.Exists(this.tempDirectory.OriginalPath).Should().BeFalse();
    }

    [Fact]
    public async Task ValidModes_DecryptOnly_ShouldPreventEncryption()
    {
        // Setup data
        await File.WriteAllBytesAsync(this.tempDirectory.OriginalPath, TestUtils.FileDataBytes);

        // Encrypt a file
        ProtectionOptions encryptOptions = new();
        Protector encryptProtector = new(NullLogger<Protector>.Instance, encryptOptions);
        await encryptProtector.ProtectFile(this.tempDirectory.OriginalFile, CancellationToken.None);

        // Only decryption allowed
        ProtectionOptions options = new(ValidModes: ProtectionModes.Decrypt);
        Protector protector = new(NullLogger<Protector>.Instance, options);

        // Decrypt should succeed
        Result decryptResult = await protector.ProtectFile(this.tempDirectory.EncryptedFile, CancellationToken.None);
        decryptResult.IsSuccess.Should().BeTrue();
        File.Exists(this.tempDirectory.EncryptedPath).Should().BeFalse();
        File.Exists(this.tempDirectory.OriginalPath).Should().BeTrue();

        // Encrypt should fail
        Result encryptResult = await protector.ProtectFile(this.tempDirectory.OriginalFile, CancellationToken.None);
        encryptResult.IsFailure.Should().BeTrue();
        File.Exists(this.tempDirectory.EncryptedPath).Should().BeFalse();
        File.Exists(this.tempDirectory.OriginalPath).Should().BeTrue();
    }

    [Fact]
    public async Task EncryptedExtension_CustomSuffix_ShouldUseGivenExtension()
    {
        // Setup data
        await File.WriteAllBytesAsync(this.tempDirectory.OriginalPath, TestUtils.FileDataBytes);

        // Setup custom extension
        const string CUSTOM_EXT = ".crypt";
        ProtectionOptions options = new(EncryptedExtension: CUSTOM_EXT);
        Protector protector = new(NullLogger<Protector>.Instance, options);

        // Encrypt should succeed with custom extension
        Result result = await protector.ProtectFile(this.tempDirectory.OriginalFile, CancellationToken.None);
        result.IsSuccess.Should().BeTrue();
        string encryptedPath = this.tempDirectory.OriginalPath + CUSTOM_EXT;
        File.Exists(encryptedPath).Should().BeTrue();
    }

    [Fact]
    public async Task DeleteFiles_False_ShouldRetainBothVersions()
    {
        // Setup data
        await File.WriteAllBytesAsync(this.tempDirectory.OriginalPath, TestUtils.FileDataBytes);

        // Setup without file deletion
        ProtectionOptions options = new(DeleteFiles: false);
        Protector protector = new(NullLogger<Protector>.Instance, options);

        // Encrypt should succeed and keep files
        Result result = await protector.ProtectFile(this.tempDirectory.OriginalFile, CancellationToken.None);
        result.IsSuccess.Should().BeTrue();
        File.Exists(this.tempDirectory.EncryptedPath).Should().BeTrue();
        File.Exists(this.tempDirectory.OriginalPath).Should().BeTrue();
    }

    /// <inheritdoc />
    public void Dispose() => this.tempDirectory.Dispose();
}
