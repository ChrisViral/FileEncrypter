using System.Buffers.Binary;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using System.ComponentModel;
using CSharpFunctionalExtensions;
using FileEncrypter.Collections;
using FileEncrypter.Tests.Utils;

namespace FileEncrypter.Tests;

public sealed class CompressionTests
{
    [Fact]
    public async Task CompressData_None_ProducesHeaderAndUnchangedPayload()
    {
        ProtectionOptions options = new(Compression: CompressionOption.None);
        Protector protector = new(NullLogger<Protector>.Instance, options);
        (PooledArray<byte> compressed, int compressedSize) = await protector.CompressData(TestUtils.FileDataBytes, CancellationToken.None);
        using (compressed)
        {
            compressedSize.Should().Be(compressed.Length);
            compressedSize.Should().Be(TestUtils.FileDataBytes.Length + sizeof(byte));
            compressed[0].Should().Be((byte)CompressionOption.None);
            compressed.AsMemory[sizeof(byte)..].Should().Equal(TestUtils.FileDataBytes);
        }
    }

    [Theory]
    [InlineData(CompressionOption.Brotli)]
    [InlineData(CompressionOption.Deflate)]
    [InlineData(CompressionOption.GZip)]
    [InlineData(CompressionOption.ZLib)]
    public async Task CompressData_CompressedOptions_ProducesHeaders(CompressionOption compression)
    {
        ProtectionOptions options = new(Compression: compression);
        Protector protector = new(NullLogger<Protector>.Instance, options);
        (PooledArray<byte> compressed, int compressedSize) = await protector.CompressData(TestUtils.FileDataBytes, CancellationToken.None);
        using (compressed)
        {
            compressed.Length.Should().BeGreaterThanOrEqualTo(compressedSize);
            compressed[0].Should().Be((byte)compression);
            int headerSize = BinaryPrimitives.ReadInt32LittleEndian(compressed.AsSpan.Slice(sizeof(byte), sizeof(int)));
            headerSize.Should().Be(TestUtils.FileDataBytes.Length);
        }
    }

    [Theory]
    [InlineData(CompressionOption.None)]
    [InlineData(CompressionOption.Brotli)]
    [InlineData(CompressionOption.Deflate)]
    [InlineData(CompressionOption.GZip)]
    [InlineData(CompressionOption.ZLib)]
    public async Task CompressDecompress_AllCompressionOptions_ShouldReturnSameData(CompressionOption compression)
    {
        ProtectionOptions options = new(Compression: compression);
        Protector protector = new(NullLogger<Protector>.Instance, options);
        (PooledArray<byte> compressed, int compressedSize) = await protector.CompressData(TestUtils.FileDataBytes, CancellationToken.None);
        using (compressed)
        {
            (PooledArray<byte> decompressed, int decompressedSize) = await Protector.DecompressData(compressed, compressedSize, CancellationToken.None);
            using (decompressed)
            {
                decompressedSize.Should().Be(TestUtils.FileDataBytes.Length);
                decompressed.AsMemory.Should().BeEqualTo(TestUtils.FileDataBytes);
            }
        }
    }

    [Theory]
    [InlineData(CompressionOption.None)]
    [InlineData(CompressionOption.Brotli)]
    [InlineData(CompressionOption.Deflate)]
    [InlineData(CompressionOption.GZip)]
    [InlineData(CompressionOption.ZLib)]
    public async Task EncryptDecrypt_AllCompressionOptions_ShouldReturnSameData(CompressionOption compression)
    {

        // Arrange – create a file with some content
        using TempDirectory tempDir = new();
        string originalPath = Path.Combine(tempDir.DirectoryPath, TestUtils.FILE_NAME);
        await File.WriteAllBytesAsync(originalPath, TestUtils.FileDataBytes);

        ProtectionOptions options = new(Compression: compression);
        Protector protector = new(NullLogger<Protector>.Instance, options);

        // Act – encrypt
        Result encryptResult = await protector.ProtectFile(new FileInfo(originalPath), CancellationToken.None);
        encryptResult.IsSuccess.Should().BeTrue();

        string encryptedPath = originalPath + options.EncryptedExtension;
        File.Exists(encryptedPath).Should().BeTrue();
        File.Exists(originalPath).Should().BeFalse(); // deleted after encryption

        // Act – decrypt with same settings
        Result decryptResult = await protector.ProtectFile(new FileInfo(encryptedPath), CancellationToken.None);
        decryptResult.IsSuccess.Should().BeTrue();

        File.Exists(originalPath).Should().BeTrue();
        File.Exists(encryptedPath).Should().BeFalse(); // removed after decryption

        // Verify decrypted file content
        byte[] decryptedBytes = await File.ReadAllBytesAsync(originalPath);
        decryptedBytes.Should().Equal(TestUtils.FileDataBytes);
    }

    [Fact]
    public async Task CompressData_InvalidCompressionOption_ThrowsException()
    {
        ProtectionOptions options = new(Compression: (CompressionOption)byte.MaxValue);
        Protector protector = new(NullLogger<Protector>.Instance, options);
        Func<Task> compress = async () => await protector.CompressData(TestUtils.FileDataBytes, CancellationToken.None);
        await compress.Should().ThrowAsync<InvalidEnumArgumentException>();
    }

    [Fact]
    public async Task DecompressData_InvalidCompressionOption_ThrowsException()
    {
        Protector protector = new(NullLogger<Protector>.Instance, new ProtectionOptions());
        (PooledArray<byte> compressed, int compressedSize) =  await protector.CompressData(TestUtils.FileDataBytes, CancellationToken.None);
        compressed[0] = byte.MaxValue;
        Func<Task> decompress = async () => await Protector.DecompressData(compressed, compressedSize, CancellationToken.None);
        await decompress.Should().ThrowAsync<InvalidEnumArgumentException>();
    }
}
