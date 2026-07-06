using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using System.ComponentModel;
using CSharpFunctionalExtensions;
using FileEncrypter.Collections;
using FileEncrypter.Tests.Utils;

namespace FileEncrypter.Tests;

public class CompressionTests
{
    [Fact]
    public async Task CompressData_None_ProducesHeaderAndUnchangedPayload()
    {
        ProtectionOptions options = new(Compression: CompressionOption.None);
        Protector protector = new(NullLogger<Protector>.Instance, options);

        byte[] data = "abc"u8.ToArray();
        (PooledArray<byte> compressed, int compressedSize) result = await protector.CompressData(data, CancellationToken.None).ConfigureAwait(true);

        try
        {
            PooledArray<byte> compressedArray = result.compressed;
            int size = result.compressedSize;

            compressedArray.Length.Should().Be(data.Length + 1);
            compressedArray[0].Should().Be((byte)CompressionOption.None);
            byte[] payload = compressedArray.AsMemory[1..].ToArray();
            payload.Should().Equal(data);
            size.Should().Be(compressedArray.Length);
        }
        finally
        {
            result.compressed.Dispose();
        }
    }

    [Theory]
    [InlineData(CompressionOption.Brotli)]
    [InlineData(CompressionOption.Deflate)]
    [InlineData(CompressionOption.GZip)]
    [InlineData(CompressionOption.ZLib)]
    public async Task EncryptDecrypt_AllCompressionOptions_ShouldReturnSameData(CompressionOption compression)
    {
        // Arrange – create a file with some content
        using TempDirectory tempDir = new();
        const string ORIGINAL_FILE_NAME = "sample.txt";
        string originalPath = Path.Combine(tempDir.DirectoryPath, ORIGINAL_FILE_NAME);
        byte[] originalBytes = "Hello compression test!"u8.ToArray();
        await File.WriteAllBytesAsync(originalPath, originalBytes).ConfigureAwait(true);

        ProtectionOptions options = new(Compression: compression);
        Protector protector = new(NullLogger<Protector>.Instance, options);

        // Act – encrypt
        Result encryptResult = await protector.ProtectAll(new[] { new FileInfo(originalPath) }).ConfigureAwait(true);
        encryptResult.IsSuccess.Should().BeTrue();

        string encryptedPath = originalPath + options.EncryptedExtension;
        File.Exists(encryptedPath).Should().BeTrue();
        File.Exists(originalPath).Should().BeFalse(); // deleted after encryption

        // Act – decrypt with same settings
        Protector protectorDecrypt = new(NullLogger<Protector>.Instance, options);
        Result decryptResult = await protectorDecrypt.ProtectAll(new[] { new FileInfo(encryptedPath) }).ConfigureAwait(true);
        decryptResult.IsSuccess.Should().BeTrue();

        // Verify decrypted file content
        byte[] decryptedBytes = await File.ReadAllBytesAsync(originalPath).ConfigureAwait(true);
        decryptedBytes.Should().Equal(originalBytes);

        File.Exists(encryptedPath).Should().BeFalse(); // removed after decryption
    }

    [Fact]
    public async Task CompressData_InvalidCompressionOption_ThrowsException()
    {
        const CompressionOption INVALID_COMPRESSION = (CompressionOption)99;
        ProtectionOptions options = new(Compression: INVALID_COMPRESSION);
        Protector protector = new(NullLogger<Protector>.Instance, options);

        byte[] data = "data"u8.ToArray();

        Func<Task> act = async () => await protector.CompressData(data, CancellationToken.None).ConfigureAwait(false);

        await act.Should().ThrowAsync<InvalidEnumArgumentException>().ConfigureAwait(true);
    }
}
