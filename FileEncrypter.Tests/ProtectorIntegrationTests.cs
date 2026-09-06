using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using CSharpFunctionalExtensions;
using FileEncrypter.Tests.Utils;

namespace FileEncrypter.Tests;

public sealed class ProtectorIntegrationTests : IDisposable
{
    private readonly TempDirectory tempDirectory = new();

    [Fact]
    public async Task ProtectAll_WithNoTargets_ShouldSucceed()
    {
        Protector protector = new(NullLogger<Protector>.Instance, ProtectionOptions.Default);
        Result result = await protector.ProtectAll(Array.Empty<FileSystemInfo>());
        result.IsSuccess.Should().BeTrue();
    }

    [Theory]
    [InlineData(CompressionOption.None)]
    [InlineData(CompressionOption.Brotli)]
    [InlineData(CompressionOption.Deflate)]
    [InlineData(CompressionOption.GZip)]
    [InlineData(CompressionOption.ZLib)]
    public async Task ProtectAll_RoundTrip_AllCompressionOptions_ShouldReturnSameData(CompressionOption compression)
    {
        // Write file
        await File.WriteAllBytesAsync(this.tempDirectory.OriginalPath, TestUtils.FileDataBytes);
        FileSystemInfo[] files = [this.tempDirectory.DirectoryInfo];

        // Encrypt should succeed
        ProtectionOptions options = new(Compression: compression);
        Protector protector = new(NullLogger<Protector>.Instance, options);
        Result encryptResult = await protector.ProtectAll(files);
        encryptResult.IsSuccess.Should().BeTrue();

        // Check files
        File.Exists(this.tempDirectory.EncryptedPath).Should().BeTrue();
        File.Exists(this.tempDirectory.OriginalPath).Should().BeFalse();

        // Decrypt should succeed
        Result decryptResult = await protector.ProtectAll(files);
        decryptResult.IsSuccess.Should().BeTrue();

        // Check files
        File.Exists(this.tempDirectory.EncryptedPath).Should().BeFalse();
        File.Exists(this.tempDirectory.OriginalPath).Should().BeTrue();

        // Verify decrypted file content
        byte[] decryptedBytes = await File.ReadAllBytesAsync(this.tempDirectory.OriginalPath);
        decryptedBytes.Should().Equal(TestUtils.FileDataBytes);
    }

    /// <inheritdoc />
    public void Dispose() => this.tempDirectory.Dispose();
}
