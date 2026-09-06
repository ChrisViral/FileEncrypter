using System.Security.Cryptography;
using System.Text;
using CSharpFunctionalExtensions;
using FileEncrypter.Collections;
using FileEncrypter.Tests.Utils;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;

namespace FileEncrypter.Tests;

public sealed class EncryptionTest
{
    public static TheoryData<byte[]?> TestPasswords { get; } = [Encoding.UTF8.GetBytes(string.Empty), TestUtils.PasswordBytes];

    [Fact]
    public async Task ProtectUnprotect_DefaultOptions_ShouldProduceInput()
    {
        await ProtectUnprotect_WithOptions_ShouldProduceInput(ProtectionOptions.Default);
    }

    [Theory]
    [MemberData(nameof(TestPasswords))]
    public async Task ProtectUnprotect_WithPassword_ShouldProduceInput(byte[]? password)
    {
        await ProtectUnprotect_WithOptions_ShouldProduceInput(new ProtectionOptions(Password: password));
    }

    [Fact]
    public async Task ProtectUnprotect_LocalMachineScope_ShouldProduceInput()
    {
        await ProtectUnprotect_WithOptions_ShouldProduceInput(new ProtectionOptions(Scope: DataProtectionScope.LocalMachine));
    }

    private static async Task ProtectUnprotect_WithOptions_ShouldProduceInput(ProtectionOptions options)
    {
        // Setup protector
        Protector protector = new(NullLogger<Protector>.Instance, options);

        // Protect data
        Result<(PooledArray<byte>, int)> encryptResult = await protector.ProtectData(TestUtils.FileDataBytes, CancellationToken.None);
        encryptResult.IsSuccess.Should().BeTrue();

        // Extract data
        (PooledArray<byte> encrypted, int encryptedSize) = encryptResult.Value;
        using (encrypted)
        {
            // Validates different from original
            Memory<byte> encryptedData = encrypted.AsMemory[..encryptedSize];
            encryptedData.Should().NotBeEmpty();
            encryptedData.Should().NotBeEqualTo(TestUtils.FileDataBytes);

            // Unprotect data
            Result<(PooledArray<byte>, int)> decryptResult = await protector.UnprotectData(encryptedData, CancellationToken.None);
            decryptResult.IsSuccess.Should().BeTrue();

            // Extract data
            (PooledArray<byte> decrypted, int decryptedSize) = decryptResult.Value;
            using (decrypted)
            {
                // Validates same as original
                Memory<byte> decryptedData = decrypted.AsMemory[..decryptedSize];
                decryptedData.Should().NotBeEmpty();
                decryptedData.Should().BeEqualTo(TestUtils.FileDataBytes);
            }
        }
    }

    [Fact]
    public async Task Unprotect_WithWrongPassword_ShouldFail()
    {
        // Setup protector
        ProtectionOptions passwordOptions = new(Password: TestUtils.PasswordBytes);
        Protector passwordProtector = new(NullLogger<Protector>.Instance, passwordOptions);

        // Protect data
        Result<(PooledArray<byte>, int)> encryptResult = await passwordProtector.ProtectData(TestUtils.FileDataBytes, CancellationToken.None);
        encryptResult.IsSuccess.Should().BeTrue();

        // Extract data
        (PooledArray<byte> encrypted, int encryptedSize) = encryptResult.Value;
        using (encrypted)
        {
            // Validates different from original
            Memory<byte> encryptedData = encrypted.AsMemory[..encryptedSize];
            ProtectionOptions noPasswordOptions = ProtectionOptions.Default;
            Protector noPasswordProtector = new(NullLogger<Protector>.Instance, noPasswordOptions);

            // Unprotect should throw
            Func<Task> decompress = async () => await noPasswordProtector.UnprotectData(encryptedData, CancellationToken.None);
            await decompress.Should().ThrowAsync<CryptographicException>();
        }
    }
}
