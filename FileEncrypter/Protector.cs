using System.Diagnostics;
using System.Numerics;
using System.Security.Cryptography;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;

namespace FileEncrypter;

[PublicAPI]
public sealed partial class Protector(ILogger<Protector> logger, in ProtectionOptions options) : IDisposable
{
    private const string ENCRYPTED_EXTENSION = ".enc";

    private readonly CancellationTokenSource source = new();
    private readonly ProtectionOptions options = options;

    private ILogger Logger { get; } = logger;

    public void Dispose() => this.source.Dispose();

    public async Task<bool> ProtectAll(FileSystemInfo[] targets)
    {
        bool success = true;
        foreach (FileSystemInfo target in targets)
        {
            switch (target)
            {
                case FileInfo file:
                    this.source.CancelAfter(this.options.FileTimeout);
                    success &= await ProtectFile(file, this.source.Token).ConfigureAwait(false);
                    this.source.TryReset();
                    break;

                case DirectoryInfo directory:
                    success &= await ProtectDirectory(directory).ConfigureAwait(false);
                    break;

                default:
                    LogUnidentifiedFilesysteminfoObjectTypenameTarget(this.Logger, target.GetType().FullName!, target);
                    success = false;
                    break;
            }
        }
        return success;
    }

    public async Task<bool> ProtectDirectory(DirectoryInfo directory)
    {
        bool noErrors = true;
        foreach (FileInfo file in directory.EnumerateFiles(this.options.SearchPattern, this.options.SearchOption))
        {
            this.source.CancelAfter(this.options.FileTimeout);
            noErrors &= await ProtectFile(file, this.source.Token).ConfigureAwait(false);
            this.source.TryReset();
        }
        return noErrors;
    }

    public async Task<bool> ProtectFile(FileInfo file, CancellationToken token)
    {
        LogActionFileFilename(this.Logger, file.Extension is ENCRYPTED_EXTENSION ? "Decrypting" : "Encrypting", file.FullName);
        try
        {
            // Open and read file
            if (file.Length >= int.MaxValue)
            {
                LogFileFilenameTooLargeToHandle(this.Logger, file.FullName);
                return false;
            }

            int length = (int)file.Length;
            using PooledArray<byte> data = new(length);
            await using (FileStream readStream = file.OpenRead())
            {
                await readStream.ReadExactlyAsync(data.AsMemory, token).ConfigureAwait(false);
            }

            switch (file.Extension)
            {
                case ENCRYPTED_EXTENSION when this.options.ValidModes.HasFlagFast(ProtectionModes.Decrypt):
                    if (!TryUnprotectData(data.AsMemory, out PooledArray<byte> decrypted, out int decryptedSize)) return false;

                    using (decrypted)
                    {
                        await SaveData(decrypted.AsMemory[..decryptedSize], Path.ChangeExtension(file.FullName, null), token).ConfigureAwait(false);
                    }
#if !DEBUG
                    file.Delete();
#endif
                    return true;

                case ENCRYPTED_EXTENSION:
                    LogEncryptionNotEnabledIgnoringFileFilename(this.Logger, file.FullName);
                    return false;

                case not null when this.options.ValidModes.HasFlagFast(ProtectionModes.Encrypt):
                {
                    if (!TryProtectData(data.AsMemory, out PooledArray<byte> encrypted, out int encryptedSize)) return false;

                    using (encrypted)
                    {
                        await SaveData(encrypted.AsMemory[..encryptedSize], file.FullName + ENCRYPTED_EXTENSION, token).ConfigureAwait(false);
                    }
#if !DEBUG
                    file.Delete();
#endif
                    return true;
                }

                default:
                    LogDecryptionNotEnabledIgnoringFileFilename(this.Logger, file.FullName);
                    return false;
            }
        }
        catch (Exception e)
        {
            //Log any exceptions
            LogErrorHappenedForFileFilename(this.Logger, file.FullName, e);
            return false;
        }
    }

    private bool TryUnprotectData(Memory<byte> data, out PooledArray<byte> decrypted, out int decryptedSize)
    {
        PooledArray<byte> buffer = new(data.Length);
        try
        {
            if (ProtectedData.TryUnprotect(data.Span, this.options.Scope, buffer.AsSpan, out decryptedSize, this.options.Password))
            {
                decrypted = buffer;
                return true;
            }

            throw new UnreachableException("Decrypted data should never be larger than encrypted data.");
        }
        catch (Exception e)
        {
            this.Logger.LogError(e, "Error while encrypting data");
            buffer.Dispose();
            decrypted = default;
            decryptedSize = 0;
            return false;
        }
    }

    private bool TryProtectData(Memory<byte> data, out PooledArray<byte> encrypted, out int encryptedSize)
    {
        uint bufferSize = BitOperations.RoundUpToPowerOf2((uint)data.Length + 64U) / 2U;
        do
        {
            bufferSize = Math.Min(bufferSize * 2U, int.MaxValue);
            PooledArray<byte> buffer = new((int)bufferSize);
            try
            {
                if (ProtectedData.TryProtect(data.Span, this.options.Scope, buffer.AsSpan, out encryptedSize, this.options.Password))
                {
                    encrypted = buffer;
                    return true;
                }
            }
            catch (Exception e)
            {
                this.Logger.LogError(e, "Error while encrypting data");
                buffer.Dispose();
                encrypted = default;
                encryptedSize = 0;
                return false;
            }

            buffer.Dispose();
        }
        while (bufferSize < int.MaxValue);

        this.Logger.LogError("Failed to encrypt data due to output being too large");
        encrypted = default;
        encryptedSize = 0;
        return false;
    }

    private static async Task SaveData(Memory<byte> data, string path, CancellationToken token)
    {
        if (File.Exists(path))
        {
            File.Delete(path);
        }

        await using FileStream writeStream = File.Create(path);
        await writeStream.WriteAsync(data, token).ConfigureAwait(false);
    }
}
