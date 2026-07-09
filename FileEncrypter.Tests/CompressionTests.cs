using System.Buffers.Binary;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using System.ComponentModel;
using FileEncrypter.Collections;
using FileEncrypter.Tests.Utils;

namespace FileEncrypter.Tests;

public sealed class CompressionTests
{
    [Fact]
    public async Task CompressData_None_ProducesHeaderAndUnchangedPayload()
    {
        // Setup data
        ProtectionOptions options = new(Compression: CompressionOption.None);
        Protector protector = new(NullLogger<Protector>.Instance, options);

        // Compress and check length and headers
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
        // Setup data
        ProtectionOptions options = new(Compression: compression);
        Protector protector = new(NullLogger<Protector>.Instance, options);

        // Compress and check length and headers
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
        // Setup data
        ProtectionOptions options = new(Compression: compression);
        Protector protector = new(NullLogger<Protector>.Instance, options);

        // Compress
        (PooledArray<byte> compressed, int compressedSize) = await protector.CompressData(TestUtils.FileDataBytes, CancellationToken.None);
        using (compressed)
        {
            // Decompress and check data
            (PooledArray<byte> decompressed, int decompressedSize) = await Protector.DecompressData(compressed, compressedSize, CancellationToken.None);
            using (decompressed)
            {
                decompressedSize.Should().Be(TestUtils.FileDataBytes.Length);
                decompressed.AsMemory.Should().BeEqualTo(TestUtils.FileDataBytes);
            }
        }
    }

    [Fact]
    public async Task CompressData_InvalidCompressionOption_ThrowsException()
    {
        // Setup data
        ProtectionOptions options = new(Compression: (CompressionOption)byte.MaxValue);
        Protector protector = new(NullLogger<Protector>.Instance, options);

        // Compression should throw
        Func<Task> compress = async () => await protector.CompressData(TestUtils.FileDataBytes, CancellationToken.None);
        await compress.Should().ThrowAsync<InvalidEnumArgumentException>();
    }

    [Fact]
    public async Task DecompressData_InvalidCompressionOption_ThrowsException()
    {
        // Setup data
        ProtectionOptions options = new();
        Protector protector = new(NullLogger<Protector>.Instance, options);

        // Compress
        (PooledArray<byte> compressed, int compressedSize) =  await protector.CompressData(TestUtils.FileDataBytes, CancellationToken.None);

        // Corrupt file
        compressed[0] = byte.MaxValue;

        // Decompression should throw
        Func<Task> decompress = async () => await Protector.DecompressData(compressed, compressedSize, CancellationToken.None);
        await decompress.Should().ThrowAsync<InvalidEnumArgumentException>();
    }
}
