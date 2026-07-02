using System.Buffers.Binary;
using System.Diagnostics;
using System.IO.Compression;
using System.Numerics;
using System.Security.Cryptography;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;

namespace FileEncrypter;

/// <summary>
/// File protection API
/// </summary>
/// <param name="logger">Logger instance</param>
/// <param name="options">Protection options</param>
[PublicAPI]
public sealed partial class Protector(ILogger<Protector> logger, in ProtectionOptions options) : IDisposable
{
    /// <summary>
    /// Encrypted file extension
    /// </summary>
    private const string ENCRYPTED_EXTENSION = ".enc";

    private readonly CancellationTokenSource source = new();
    private readonly ProtectionOptions options = options;

    /// <summary>
    /// Logger instance
    /// </summary>
    private ILogger Logger { get; } = logger;

    /// <inheritdoc/>
    public void Dispose() => this.source.Dispose();

    /// <summary>
    /// Protects all files and folders given
    /// </summary>
    /// <param name="targets">Array of files and folders to protect</param>
    /// <returns>True if no errors occured, otherwise false</returns>
    public async Task<bool> ProtectAll(ReadOnlyMemory<FileSystemInfo> targets)
    {
        bool success = true;
        for (int i = 0; i < targets.Length; i++)
        {
            FileSystemInfo target = targets.Span[i];
            switch (target)
            {
                case FileInfo file:
                    // Compress files immediately
                    this.source.CancelAfter(this.options.FileTimeout);
                    success &= await ProtectFile(file, this.source.Token).ConfigureAwait(false);
                    this.source.TryReset();
                    break;

                case DirectoryInfo directory:
                    // Compress all files in folder
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

    /// <summary>
    /// Protects all the valid files in a given directory
    /// </summary>
    /// <param name="directory">Directory to look through</param>
    /// <returns>True if no errors occured, otherwise false</returns>
    public async Task<bool> ProtectDirectory(DirectoryInfo directory)
    {
        // Enumerate and compress all files
        bool success = true;
        foreach (FileInfo file in directory.EnumerateFiles(this.options.SearchPattern, this.options.SearchOption))
        {
            this.source.CancelAfter(this.options.FileTimeout);
            success &= await ProtectFile(file, this.source.Token).ConfigureAwait(false);
            this.source.TryReset();
        }
        return success;
    }

    /// <summary>
    /// Protects a given file
    /// </summary>
    /// <param name="file">File to protect</param>
    /// <param name="token">Cancellation token</param>
    /// <returns>True if no errors occured, otherwise false</returns>
    public async Task<bool> ProtectFile(FileInfo file, CancellationToken token)
    {
        // Check if file can be decrypted
        if (file.Extension is ENCRYPTED_EXTENSION && !this.options.ValidModes.HasFlagFast(ProtectionModes.Decrypt))
        {
            LogDecryptionNotEnabledIgnoringFileFilename(this.Logger, file.FullName);
            return true;
        }

        // Check if file can be encrypted
        if (file.Extension is not ENCRYPTED_EXTENSION && !this.options.ValidModes.HasFlagFast(ProtectionModes.Encrypt))
        {
            LogEncryptionNotEnabledIgnoringFileFilename(this.Logger, file.FullName);
            return true;
        }

        LogActionFileFilename(this.Logger, file.Extension is ENCRYPTED_EXTENSION ? "Decrypting" : "Encrypting", file.FullName);

        try
        {
            // Make sure file size is valid
            if (file.Length >= int.MaxValue)
            {
                LogFileFilenameTooLargeToHandle(this.Logger, file.FullName);
                return false;
            }

            // Read file data
            int length = (int)file.Length;
            using PooledArray<byte> data = new(length);
            await using (FileStream readStream = file.OpenRead())
            {
                await readStream.ReadExactlyAsync(data.AsMemory, token).ConfigureAwait(false);
            }

            // Handle file
            return file.Extension switch
            {
                ENCRYPTED_EXTENSION => await DecryptFile(file, data, token).ConfigureAwait(false),
                _                   => await EncryptFile(file, data, token).ConfigureAwait(false)
            };
        }
        catch (Exception e)
        {
            //Log any exceptions
            LogErrorHappenedForFileFilename(this.Logger, file.FullName, e);
            return false;
        }
    }

    /// <summary>
    /// Encrypts a given file
    /// </summary>
    /// <param name="file">File to encrypt</param>
    /// <param name="data">Raw file data data</param>
    /// <param name="token">Cancellation token</param>
    /// <returns>True if no errors occured, otherwise false</returns>
    private async Task<bool> EncryptFile(FileInfo file, PooledArray<byte> data, CancellationToken token)
    {
        PooledArray<byte> encrypted;
        int encryptedSize;
        if (this.options.Compress)
        {
            // Compress file data before encryption
            using PooledArray<byte> compressed = CompressData(data.AsSpan, out int compressedSize);
            if (!TryProtectData(compressed.AsMemory[..compressedSize], out encrypted, out encryptedSize)) return false;
        }
        else
        {
            // Simply encrypt file
            if (!TryProtectData(data.AsMemory, out encrypted, out encryptedSize)) return false;
        }

        using (encrypted)
        {
            // Save encrypted file to disk
            ReadOnlyMemory<byte> encryptedMemory = encrypted.AsMemory[..encryptedSize];
            string path = file.FullName + ENCRYPTED_EXTENSION;
            await SaveData(encryptedMemory, path, token).ConfigureAwait(false);
        }

        // Delete old file if needed
        if (this.options.DeleteFiles)
        {
            file.Delete();
        }

        return true;
    }

    /// <summary>
    /// Decrypts a given file
    /// </summary>
    /// <param name="file">File to decrypt</param>
    /// <param name="data">Encrypted file data</param>
    /// <param name="token">Cancellatio token</param>
    /// <returns>True if no errors occured, otherwise false</returns>
    private async Task<bool> DecryptFile(FileInfo file, PooledArray<byte> data, CancellationToken token)
    {
        // Decrypt file
        if (!TryUnprotectData(data.AsMemory, out PooledArray<byte> decrypted, out int decryptedSize)) return false;

        using (decrypted)
        {
            ReadOnlyMemory<byte> decryptedMemory = decrypted.AsMemory[..decryptedSize];
            string path = Path.ChangeExtension(file.FullName, null);
            if (this.options.Compress)
            {
                // Decompress file before saving
                using PooledArray<byte> decompressed = DecompressData(decryptedMemory.Span, out int decompressedSize);
                await SaveData(decompressed.AsMemory[..decompressedSize], path, token).ConfigureAwait(false);
            }
            else
            {
                // Simply save decrypted file
                await SaveData(decryptedMemory, path, token).ConfigureAwait(false);
            }
        }

        // Delete old file if needed
        if (this.options.DeleteFiles)
        {
            file.Delete();
        }

        return true;
    }

    /// <summary>
    /// Tries to unprotect the data from a given file
    /// </summary>
    /// <param name="data">Data to unprotect</param>
    /// <param name="decrypted">Decrypted data output</param>
    /// <param name="decryptedSize">Decrypted data size output</param>
    /// <returns><see langword="true"/> if the unprotection was a success, otherwise <see langword="false"/></returns>
    /// <exception cref="UnreachableException">If the decrypted data ends up longer than expected</exception>
    private bool TryUnprotectData(Memory<byte> data, out PooledArray<byte> decrypted, out int decryptedSize)
    {
        // Decryption will always make file smaller, so simply get buffer file of same size
        PooledArray<byte> buffer = new(data.Length);
        try
        {
            // Try decrypting file
            if (ProtectedData.TryUnprotect(data.Span, this.options.Scope, buffer.AsSpan, out decryptedSize, this.options.Password))
            {
                decrypted = buffer;
                return true;
            }

            throw new UnreachableException("Decrypted data should never be larger than encrypted data.");
        }
        catch (Exception e)
        {
            // In case of error, dispose buffer
            this.Logger.LogError(e, "Error while encrypting data");
            buffer.Dispose();
            decrypted = default;
            decryptedSize = 0;
            return false;
        }
    }

    /// <summary>
    /// Tries to protect the data from a given file
    /// </summary>
    /// <param name="data">Data to protect</param>
    /// <param name="encrypted">Encrypted data output</param>
    /// <param name="encryptedSize">Encrypted data size output</param>
    /// <returns><see langword="true"/> if the protection was a success, otherwise <see langword="false"/></returns>
    private bool TryProtectData(Memory<byte> data, out PooledArray<byte> encrypted, out int encryptedSize)
    {
        // Encryption will make file larger, so get a larger buffer to start with
        uint bufferSize = BitOperations.RoundUpToPowerOf2((uint)data.Length + 64U) / 2U;
        do
        {
            // Increase buffer size and get buffer
            bufferSize = Math.Min(bufferSize * 2U, int.MaxValue);
            PooledArray<byte> buffer = new((int)bufferSize);
            try
            {
                // Try encryption file
                if (ProtectedData.TryProtect(data.Span, this.options.Scope, buffer.AsSpan, out encryptedSize, this.options.Password))
                {
                    encrypted = buffer;
                    return true;
                }
            }
            catch (Exception e)
            {
                // In case of error, dispose of buffer
                this.Logger.LogError(e, "Error while encrypting data");
                buffer.Dispose();
                encrypted = default;
                encryptedSize = 0;
                return false;
            }

            // Buffer too smal, dispose and try again with larger buffer
            buffer.Dispose();
        }
        while (bufferSize < int.MaxValue); // Once max size reached, abort

        this.Logger.LogError("Failed to encrypt data due to output being too large");
        encrypted = default;
        encryptedSize = 0;
        return false;
    }

    /// <summary>
    /// Decompresses the given file data
    /// </summary>
    /// <param name="data">Data to decompress</param>
    /// <param name="decompressedSize">Decompressed size output</param>
    /// <returns>The decompressed file data</returns>
    /// <exception cref="InvalidOperationException">If the data failed to decompress</exception>
    private static PooledArray<byte> DecompressData(ReadOnlySpan<byte> data, out int decompressedSize)
    {
        // Get decompressed size from file header, and make buffer of that size
        decompressedSize = BinaryPrimitives.ReadInt32LittleEndian(data);
        PooledArray<byte> decompressed = new(decompressedSize);

        // Decompress file
        if (!BrotliDecoder.TryDecompress(data[sizeof(int)..], decompressed.AsSpan, out int written) || written != decompressedSize)
        {
            // In case of error, dispose buffer
            decompressed.Dispose();
            throw new InvalidOperationException("Could not decompress data correctly");
        }

        return decompressed;
    }

    /// <summary>
    /// Compresses the given file data
    /// </summary>
    /// <param name="data">Data to compress</param>
    /// <param name="compressedSize">Compressed size output</param>
    /// <returns>The compressed file data</returns>
    /// <exception cref="InvalidOperationException">If the data fails to compress</exception>
    private static PooledArray<byte> CompressData(ReadOnlySpan<byte> data, out int compressedSize)
    {
        // Get max compressed size buffer
        PooledArray<byte> compressed = new(BrotliEncoder.GetMaxCompressedLength(data.Length) + sizeof(int));

        // Compress file
        if (!BrotliEncoder.TryCompress(data, compressed.AsSpan[sizeof(int)..], out compressedSize))
        {
            // In case of error, dispose buffer
            compressed.Dispose();
            throw new InvalidOperationException("Could not compress data correctly");
        }

        // Write original file size to header
        compressedSize += sizeof(int);
        BinaryPrimitives.WriteInt32LittleEndian(compressed.AsSpan, data.Length);
        return compressed;
    }

    /// <summary>
    /// Saves the given file data to a file
    /// </summary>
    /// <param name="data">File data to save</param>
    /// <param name="path">Save file path</param>
    /// <param name="token">Cancellation token</param>
    private static async Task SaveData(ReadOnlyMemory<byte> data, string path, CancellationToken token)
    {
        // If file already exists at location, delete it
        if (File.Exists(path))
        {
            File.Delete(path);
        }

        // Write new file data
        await using FileStream writeStream = File.Create(path);
        await writeStream.WriteAsync(data, token).ConfigureAwait(false);
    }
}
