using System.Buffers.Binary;
using System.Security.Cryptography;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;

namespace FileEncrypter.Tests;

public class CompressionTests
{
    [Theory]
    [InlineData(CompressionOption.None)]
    [InlineData(CompressionOption.Brotli)]
    [InlineData(CompressionOption.Deflate)]
    [InlineData(CompressionOption.GZip)]
    [InlineData(CompressionOption.ZLib)]
    public async Task CompressAndDecompress_ShouldMaintainDataIntegrity(CompressionOption option)
    {
        // Arrange
        Protector protector = new(NullLogger<Protector>.Instance, new ProtectionOptions
        {
            Compression = option,
            Password = "testpassword"u8.ToArray(),
            Scope = DataProtectionScope.CurrentUser
        });

        // Create a mix of small and large data to ensure various compression behaviors are triggered
        byte[] originalData = System.Text.Encoding.UTF8.GetBytes($"Test string with some variety: {Guid.NewGuid()} " + new string('A', 2048));

        // Act
        (PooledArray<byte> compressed, int compressedSize) = await protector.CompressData(originalData, CancellationToken.None);

        // Assert Header and Size
        compressed.Length.Should().Be(compressedSize);
        compressed[0].Should().Be((byte)option);

        if (option != CompressionOption.None)
        {
            int expectedOriginalSize = BinaryPrimitives.ReadInt32LittleEndian(compressed.AsSpan.Slice(1, 4));
            expectedOriginalSize.Should().Be(originalData.Length);
        }

        // Decompress
        (PooledArray<byte> decompressed, int decompressedSize) = await Protector.DecompressData(compressed, compressedSize, CancellationToken.None);

        // Assert Integrity
        decompressedSize.Should().Be(originalData.Length);
        decompressed.AsSpan.ToArray().Should().Equal(originalData);
    }

    [Fact]
    public async Task CompressData_NoneOption_ShouldKeepOriginalLengthPlusHeader()
    {
        // Arrange
        byte[] data = "Hello World"u8.ToArray();
        Protector protector = new(NullLogger<Protector>.Instance, new ProtectionOptions { Compression = CompressionOption.None });

        // Act
        (_, int compressedSize) = await protector.CompressData(data, CancellationToken.None);

        // Assert
        // Header: 1 byte type + 4 bytes length = 5 bytes header (Wait, the code says NONCOMPRESSED_HEADER_SIZE is sizeof(byte)=1)
        // Looking at Protector.cs line 360-362: compressedSize is set to data.Length + 1?
        // Actually it's result of new PooledArray<byte>(data.Length + NONCOMPRESSED_HEADER_SIZE).
        // Let's verify the actual behavior.
        compressedSize.Should().Be(data.Length + 1);
    }

    [Fact]
    public async Task GrowthLoop_ShouldHandleLargeRandomData()
    {
        // Arrange
        // Use random noise which is hard to compress, forcing potential buffer growth re-tries
        Random random = new();
        byte[] data = new byte[5000];
        random.NextBytes(data);

        Protector protector = new(NullLogger<Protector>.Instance, new ProtectionOptions
        {
            Compression = CompressionOption.Deflate
        });

        // Act & Assert: Should succeed without throwing despite buffer expansion needs
        Func<Task<(PooledArray<byte> compressed, int compressedSize)>> action = async () => await protector.CompressData(data, CancellationToken.None);
        await action.Should().NotThrowAsync();
    }

    [Fact]
    public async Task DecompressData_WithCorruptHeader_ShouldThrowInvalidOperationException()
    {
        // Arrange
        byte[] data = "Some data"u8.ToArray();
        Protector protector = new(NullLogger<Protector>.Instance, new ProtectionOptions { Compression = CompressionOption.None });
        (PooledArray<byte> compressed, _) = await protector.CompressData(data, CancellationToken.None);

        // Corrupt the size in the header (index 1-4) to be much larger than actual buffer
        BinaryPrimitives.WriteInt32LittleEndian(compressed.AsSpan.Slice(1, 4), int.MaxValue);

        // Act & Assert
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            Protector.DecompressData(compressed, compressed.Length, CancellationToken.None));
    }
}
