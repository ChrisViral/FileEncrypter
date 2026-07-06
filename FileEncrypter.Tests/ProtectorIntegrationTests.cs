using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using CSharpFunctionalExtensions;
using FileEncrypter.Tests.Utils;

namespace FileEncrypter.Tests;

public class ProtectorIntegrationTests
{
    [Fact]
    public async Task MixedFiles_WithModeRestriction_FailureCount()
    {
        // Create a plain file that will be encrypted.
        using TempDirectory tempDir = new();
        string plainPath = Path.Combine(tempDir.DirectoryPath, "plain.txt");
        await File.WriteAllBytesAsync(plainPath, "secret"u8.ToArray()).ConfigureAwait(true);

        // Create another file and encrypt it without deleting the original so we have an already-encrypted file.
        string sourceToEncryptPath = Path.Combine(tempDir.DirectoryPath, "toEncrypt.txt");
        await File.WriteAllBytesAsync(sourceToEncryptPath, "keep"u8.ToArray()).ConfigureAwait(true);

        ProtectionOptions encryptOptions = new(ValidModes: ProtectionModes.Encrypt, DeleteFiles: false);
        Protector encryptProtector = new(NullLogger<Protector>.Instance, encryptOptions);
        Result encResult = await encryptProtector.ProtectFile(new FileInfo(sourceToEncryptPath), CancellationToken.None).ConfigureAwait(true);
        encResult.IsSuccess.Should().BeTrue();

        // Path to the encrypted file.
        string alreadyEncryptedPath = sourceToEncryptPath + encryptOptions.EncryptedExtension;
        // Ensure it exists.
        File.Exists(alreadyEncryptedPath).Should().BeTrue();

        // Now try to process both files with only encryption mode allowed (no decryption).
        ProtectionOptions optionsOnlyEncrypt = new(ValidModes: ProtectionModes.Encrypt);
        Protector protector = new(NullLogger<Protector>.Instance, optionsOnlyEncrypt);
        Result result = await protector.ProtectAll(new[] { new FileInfo(plainPath), new FileInfo(alreadyEncryptedPath) }).ConfigureAwait(true);

        // One file should fail (the already encrypted one).
        result.IsFailure.Should().BeTrue();
        result.Error.Should().Contain("1 failures while protecting data");

        // The plain file should be removed and replaced by an encrypted copy.
        string expectedEncryptedPlain = plainPath + optionsOnlyEncrypt.EncryptedExtension;
        File.Exists(plainPath).Should().BeFalse();
        File.Exists(expectedEncryptedPlain).Should().BeTrue();

        // The already-encrypted file should remain unchanged.
        File.Exists(alreadyEncryptedPath).Should().BeTrue();
    }

    [Fact]
    public async Task CustomEncryptedExtension_ShouldEncryptAndDecryptCorrectly()
    {
        using TempDirectory tempDir = new();
        string plainPath = Path.Combine(tempDir.DirectoryPath, "plain.txt");
        await File.WriteAllBytesAsync(plainPath, "content"u8.ToArray()).ConfigureAwait(true);

        const string CUSTOM_EXT = ".myenc";
        ProtectionOptions options = new(EncryptedExtension: CUSTOM_EXT);
        Protector encryptor = new(NullLogger<Protector>.Instance, options);

        Result encResult = await encryptor.ProtectAll(new[] { new FileInfo(plainPath) }).ConfigureAwait(true);
        encResult.IsSuccess.Should().BeTrue();

        string encryptedPath = plainPath + CUSTOM_EXT;
        File.Exists(encryptedPath).Should().BeTrue();
        File.Exists(plainPath).Should().BeFalse();

        Protector decryptor = new(NullLogger<Protector>.Instance, options);
        Result decResult = await decryptor.ProtectAll(new[] { new FileInfo(encryptedPath) }).ConfigureAwait(true);
        decResult.IsSuccess.Should().BeTrue();

        File.Exists(plainPath).Should().BeTrue();
        File.Exists(encryptedPath).Should().BeFalse();

        byte[] originalBytes = await File.ReadAllBytesAsync(plainPath).ConfigureAwait(true);
        originalBytes.Should().Equal("content"u8.ToArray());
    }

    [Fact]
    public async Task ProtectDirectory_AllDirectories_EncryptAllMatchingFiles()
    {
        using TempDirectory tempDir = new();

        // Root level .txt file.
        string rootTxtPath = Path.Combine(tempDir.DirectoryPath, "root.txt");
        await File.WriteAllBytesAsync(rootTxtPath, "root"u8.ToArray()).ConfigureAwait(true);

        // Subdirectory with a .txt and a .log file.
        DirectoryInfo subdir = Directory.CreateDirectory(Path.Combine(tempDir.DirectoryPath, "sub"));
        string subTxtPath = Path.Combine(subdir.FullName, "sub.txt");
        await File.WriteAllBytesAsync(subTxtPath, "sub"u8.ToArray()).ConfigureAwait(true);
        string subLogPath = Path.Combine(subdir.FullName, "log.log");
        await File.WriteAllBytesAsync(subLogPath, "logdata"u8.ToArray()).ConfigureAwait(true);

        // Nested sub-sub directory with a .txt file.
        DirectoryInfo nested = Directory.CreateDirectory(Path.Combine(subdir.FullName, "nested"));
        string nestedTxtPath = Path.Combine(nested.FullName, "nest.txt");
        await File.WriteAllBytesAsync(nestedTxtPath, "nest"u8.ToArray()).ConfigureAwait(true);

        ProtectionOptions options = new(SearchPattern: "*.txt", SearchOption: SearchOption.AllDirectories);

        Protector protector = new(NullLogger<Protector>.Instance, options);
        Result result = await protector.ProtectDirectory(new DirectoryInfo(tempDir.DirectoryPath)).ConfigureAwait(true);
        result.IsSuccess.Should().BeTrue();

        string rootEncrypted = rootTxtPath + options.EncryptedExtension;
        string subEncrypted = subTxtPath + options.EncryptedExtension;
        string nestedEncrypted = nestedTxtPath + options.EncryptedExtension;

        File.Exists(rootEncrypted).Should().BeTrue();
        File.Exists(subEncrypted).Should().BeTrue();
        File.Exists(nestedEncrypted).Should().BeTrue();

        File.Exists(rootTxtPath).Should().BeFalse();
        File.Exists(subTxtPath).Should().BeFalse();
        File.Exists(nestedTxtPath).Should().BeFalse();

        // The .log file should remain unchanged.
        File.Exists(subLogPath).Should().BeTrue();
    }

    [Fact]
    public async Task ProtectDirectory_TopDirectoryOnly_ShouldNotProcessSubfolder()
    {
        using TempDirectory tempDir = new();

        string rootTxtPath = Path.Combine(tempDir.DirectoryPath, "root.txt");
        await File.WriteAllBytesAsync(rootTxtPath, "root"u8.ToArray()).ConfigureAwait(true);

        DirectoryInfo subdir = Directory.CreateDirectory(Path.Combine(tempDir.DirectoryPath, "sub"));
        string subTxtPath = Path.Combine(subdir.FullName, "sub.txt");
        await File.WriteAllBytesAsync(subTxtPath, "sub"u8.ToArray()).ConfigureAwait(true);

        ProtectionOptions options = new(SearchPattern: "*.txt", SearchOption: SearchOption.TopDirectoryOnly);

        Protector protector = new(NullLogger<Protector>.Instance, options);
        Result result = await protector.ProtectDirectory(new DirectoryInfo(tempDir.DirectoryPath)).ConfigureAwait(true);
        result.IsSuccess.Should().BeTrue();

        string rootEncrypted = rootTxtPath + options.EncryptedExtension;
        File.Exists(rootEncrypted).Should().BeTrue();
        File.Exists(rootTxtPath).Should().BeFalse();

        // The file in the subfolder should not be processed.
        File.Exists(subTxtPath).Should().BeTrue();
    }

    [Fact]
    public async Task ProtectAll_WithNoTargets_ShouldSucceed()
    {
        Protector protector = new(NullLogger<Protector>.Instance, new ProtectionOptions());
        Result result = await protector.ProtectAll(Array.Empty<FileSystemInfo>()).ConfigureAwait(true);
        result.IsSuccess.Should().BeTrue();
    }
}
