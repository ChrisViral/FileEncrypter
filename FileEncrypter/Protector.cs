using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO.Compression;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;

namespace FileEncrypter;

/// <summary>
/// File protection API
/// </summary>
/// <param name="logger">Logger instance</param>
/// <param name="options">Protection options</param>
[PublicAPI]
public sealed partial class Protector(ILogger<Protector> logger, in ProtectionOptions options)
{
    /// <summary>
    /// Parallel loop state
    /// </summary>
    private sealed class State
    {
        /// <summary>
        /// Failure count
        /// </summary>
        public int failures;
    }

    private readonly ProtectionOptions options = options;

    /// <summary>
    /// Logger instance
    /// </summary>
    private ILogger Logger { get; } = logger;

    /// <summary>
    /// Protects all files and folders given
    /// </summary>
    /// <param name="targets">Array of files and folders to protect</param>
    /// <returns>True if no errors occured, otherwise false</returns>
    public async Task<Result> ProtectAll(ReadOnlyMemory<FileSystemInfo> targets)
    {
        State state = new();
        using CancellationTokenSource source = new();
        await Parallel.ForEachAsync(GetFilesToProtect(targets).Select(f => (f, state)),
                                    source.Token,
                                    ProtectFileParallel)
                      .ConfigureAwait(false);
        return Result.SuccessIf(state.failures is 0, $"{state.failures} failures while protecting data");
    }

    /// <summary>
    /// Protects all the valid files in a given directory
    /// </summary>
    /// <param name="directory">Directory to look through</param>
    /// <returns>True if no errors occured, otherwise false</returns>
    public async Task<Result> ProtectDirectory(DirectoryInfo directory)
    {
        State state = new();
        using CancellationTokenSource source = new();
        await Parallel.ForEachAsync(directory.EnumerateFiles(this.options.SearchPattern, this.options.SearchOption)
                                             .Select(f => (f, state)),
                                    source.Token,
                                    ProtectFileParallel)
                      .ConfigureAwait(false);
        return Result.SuccessIf(state.failures is 0, $"{state.failures} failures while protecting folder");
    }

    /// <summary>
    /// Protects a given file
    /// </summary>
    /// <param name="file">File to protect</param>
    /// <param name="token">Cancellation token</param>
    /// <returns>True if no errors occured, otherwise false</returns>
    private async Task<Result> ProtectFile(FileInfo file, CancellationToken token)
    {
        if (file.Extension == this.options.EncryptedExtension && !this.options.ValidModes.HasFlagFast(ProtectionModes.Decrypt))
        {
            LogDecryptionNotEnabledIgnoringFileFilename(this.Logger, file.FullName);
            return Result.Failure("Decryption not enabled");
        }

        // Check if file can be encrypted
        if (file.Extension != this.options.EncryptedExtension && !this.options.ValidModes.HasFlagFast(ProtectionModes.Encrypt))
        {
            LogEncryptionNotEnabledIgnoringFileFilename(this.Logger, file.FullName);
            return Result.Failure("Encryption not enabled");
        }

        LogActionFileFilename(this.Logger, file.Extension == this.options.EncryptedExtension ? "Decrypting" : "Encrypting", file.FullName);

        try
        {
            // Make sure file size is valid
            if (file.Length >= int.MaxValue)
            {
                LogFileFilenameTooLargeToHandle(this.Logger, file.FullName);
                return Result.Failure("File too large");
            }

            // Read file data
            int length = (int)file.Length;
            using PooledArray<byte> data = new(length);
            await using (FileStream readStream = file.OpenRead())
            {
                await readStream.ReadExactlyAsync(data.AsMemory, token).ConfigureAwait(false);
            }

            // Handle file
            return file.Extension == this.options.EncryptedExtension
                       ? await DecryptFile(file, data, token).ConfigureAwait(false)
                       : await EncryptFile(file, data, token).ConfigureAwait(false);
        }
        catch (Exception e)
        {
            //Log any exceptions
            LogErrorHappenedForFileFilename(this.Logger, file.FullName, e);
            return Result.Failure("Exception thrown during protection");
        }
    }

    /// <summary>
    /// Enumeratres files to protect from a list of FileSystemInfo targets
    /// </summary>
    /// <param name="targets">FileSystemInfo targets to enumerate from</param>
    /// <returns></returns>
    private IEnumerable<FileInfo?> GetFilesToProtect(ReadOnlyMemory<FileSystemInfo> targets)
    {
        for (int i = 0; i < targets.Length; i++)
        {
            FileSystemInfo target = targets.Span[i];
            switch (target)
            {
                case FileInfo file:
                    // Compress files immediately
                    yield return file;
                    break;

                case DirectoryInfo directory:
                    // Compress all files in folder
                    foreach (FileInfo file in directory.EnumerateFiles(this.options.SearchPattern, this.options.SearchOption))
                    {
                        yield return file;
                    }
                    break;

                default:
                    LogUnidentifiedFilesysteminfoObjectTypenameTarget(this.Logger, target.GetType().FullName!, target);
                    yield return null;
                    break;
            }
        }
    }

    /// <summary>
    /// Protects a given file from a parallel loop
    /// </summary>
    /// <param name="fileData">Tuple containing the file to protect and the parallel loop state</param>
    /// <param name="token">Cancellation token</param>
    private async ValueTask ProtectFileParallel((FileInfo?, State) fileData, CancellationToken token)
    {
        // Check cancellation
        token.ThrowIfCancellationRequested();

        // Make sure file isn't null
        (FileInfo? file, State state) = fileData;
        if (file is null)
        {
            Interlocked.Increment(ref state.failures);
            return;
        }

        // Setup timeout source and link to original token
        using CancellationTokenSource timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(token);
        if (this.options.FileTimeout > 0)
        {
            timeoutSource.CancelAfter(this.options.FileTimeout);
        }

        // Protect file
        Result result = await ProtectFile(file, timeoutSource.Token).ConfigureAwait(false);

        // Check for failure
        if (result.IsFailure)
        {
            Interlocked.Increment(ref state.failures);
        }
    }

    /// <summary>
    /// Encrypts a given file
    /// </summary>
    /// <param name="file">File to encrypt</param>
    /// <param name="data">Raw file data data</param>
    /// <param name="token">Cancellation token</param>
    /// <returns>True if no errors occured, otherwise false</returns>
    private async Task<Result> EncryptFile(FileInfo file, PooledArray<byte> data, CancellationToken token)
    {
        Result<(PooledArray<byte>, int)> protectResult;
        if (this.options.Compress)
        {
            // Compress file data before encryption
            using PooledArray<byte> compressed = await CompressData(data.AsSpan, out int compressedSize, token).ConfigureAwait(false);
            protectResult = await ProtectData(compressed.AsMemory[..compressedSize], token).ConfigureAwait(false);
        }
        else
        {
            // Simply encrypt file
            protectResult = await ProtectData(data.AsMemory, token).ConfigureAwait(false);
        }

        if (protectResult.IsFailure) return protectResult.ConvertFailure();

        (PooledArray<byte> encrypted, int encryptedSize) = protectResult.Value;
        using (encrypted)
        {
            // Save encrypted file to disk
            await SaveData(encrypted.AsMemory[..encryptedSize], file.FullName + this.options.EncryptedExtension, token).ConfigureAwait(false);
        }

        // Delete old file if needed
        if (this.options.DeleteFiles)
        {
            file.Delete();
        }

        return Result.Success();
    }

    /// <summary>
    /// Decrypts a given file
    /// </summary>
    /// <param name="file">File to decrypt</param>
    /// <param name="data">Encrypted file data</param>
    /// <param name="token">Cancellatio token</param>
    /// <returns>True if no errors occured, otherwise false</returns>
    private async Task<Result> DecryptFile(FileInfo file, PooledArray<byte> data, CancellationToken token)
    {
        // Decrypt file
        Result<(PooledArray<byte>, int)> unprotectResult = await UnprotectData(data.AsMemory, token).ConfigureAwait(false);
        if (unprotectResult.IsFailure) return unprotectResult.ConvertFailure();

        (PooledArray<byte> decrypted, int decryptedSize) = unprotectResult.Value;
        using (decrypted)
        {
            ReadOnlyMemory<byte> decryptedMemory = decrypted.AsMemory[..decryptedSize];
            string path = Path.ChangeExtension(file.FullName, null);
            if (this.options.Compress)
            {
                // Decompress file before saving
                using PooledArray<byte> decompressed = await DecompressData(decryptedMemory.Span, out int decompressedSize, token).ConfigureAwait(false);
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

        return Result.Success();
    }

    /// <summary>
    /// Tries to unprotect the data from a given file
    /// </summary>
    /// <param name="data">Data to unprotect</param>
    /// <param name="token">Cancellation token</param>
    /// <returns>A result object, in case of success, contains a tuple with the decrypted data output and the decrypted data size output</returns>
    /// <exception cref="UnreachableException">If the decrypted data ends up longer than expected</exception>
    private ValueTask<Result<(PooledArray<byte> decrypted, int decryptedSize)>> UnprotectData(Memory<byte> data, CancellationToken token)
    {
        // Check for cancellation
        if (token.IsCancellationRequested)
        {
            return ValueTask.FromCanceled<Result<(PooledArray<byte>, int)>>(token);
        }

        // Decryption will always make file smaller, so simply get buffer file of same size
        PooledArray<byte> buffer = new(data.Length);
        try
        {
            // Try decrypting file
            if (ProtectedData.TryUnprotect(data.Span, this.options.Scope, buffer.AsSpan, out int decryptedSize, this.options.Password))
            {
                return ValueTask.FromResult(Result.Success((buffer, decryptedSize)));
            }
        }
        catch (Exception e)
        {
            // In case of error, dispose buffer
            this.Logger.LogError(e, "Error while encrypting data");
            buffer.Dispose();
            return ValueTask.FromException<Result<(PooledArray<byte>, int)>>(e);
        }

        // This should never happen, so throw if it does
        return ValueTask.FromException<Result<(PooledArray<byte>, int)>>(new UnreachableException("Decrypted data should never be larger than encrypted data."));
    }

    /// <summary>
    /// Tries to protect the data from a given file
    /// </summary>
    /// <param name="data">Data to protect</param>
    /// <param name="token">Cancellation token</param>
    /// <returns>A result object, in case of success, contains a tuple with the encrypted data output and the encrypted data size output</returns>
    private ValueTask<Result<(PooledArray<byte> encrypted, int encryptedSize)>> ProtectData(Memory<byte> data, CancellationToken token)
    {
        // Check for cancellation
        if (token.IsCancellationRequested)
        {
            return ValueTask.FromCanceled<Result<(PooledArray<byte>, int)>>(token);
        }

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
                if (ProtectedData.TryProtect(data.Span, this.options.Scope, buffer.AsSpan, out int encryptedSize, this.options.Password))
                {
                    return ValueTask.FromResult(Result.Success((buffer, encryptedSize)));
                }
            }
            catch (Exception e)
            {
                // In case of error, dispose of buffer
                this.Logger.LogError(e, "Error while encrypting data");
                buffer.Dispose();
                return ValueTask.FromException<Result<(PooledArray<byte>, int)>>(e);
            }

            // Buffer too smal, dispose and try again with larger buffer
            buffer.Dispose();
        }
        while (bufferSize < int.MaxValue); // Once max size reached, abort

        this.Logger.LogError("Failed to encrypt data due to output being too large");
        return ValueTask.FromResult(Result.Failure<(PooledArray<byte>, int)>("Failed to encrypt data due to output being too large"));
    }

    /// <summary>
    /// Decompresses the given file data
    /// </summary>
    /// <param name="data">Data to decompress</param>
    /// <param name="decompressedSize">The decompressed data size output</param>
    /// <param name="token">Cancellation token</param>
    /// <returns>The decompressed data output</returns>
    /// <exception cref="InvalidOperationException">If the data could not be decompressed</exception>
    private static ValueTask<PooledArray<byte>> DecompressData(ReadOnlySpan<byte> data, out int decompressedSize, CancellationToken token)
    {
        // Check for cancellation
        if (token.IsCancellationRequested)
        {
            decompressedSize = 0;
            return ValueTask.FromCanceled<PooledArray<byte>>(token);
        }

        // Get decompressed size from file header, and make buffer of that size
        decompressedSize = BinaryPrimitives.ReadInt32LittleEndian(data);
        PooledArray<byte> decompressed = new(decompressedSize);

        // Decompress file
        if (!BrotliDecoder.TryDecompress(data[sizeof(int)..], decompressed.AsSpan, out int written) || written != decompressedSize)
        {
            // In case of error, dispose buffer
            decompressed.Dispose();
            decompressedSize = 0;
            return ValueTask.FromException<PooledArray<byte>>(new InvalidOperationException("Could not decompress data correctly"));
        }

        return ValueTask.FromResult(decompressed);
    }

    /// <summary>
    /// Compresses the given file data
    /// </summary>
    /// <param name="data">Data to compress</param>
    /// <param name="compressedSize">The compressed data size output</param>
    /// <param name="token">Cancellation token</param>
    /// <returns>The compressed data output</returns>
    /// <exception cref="InvalidOperationException">If the data could not be compressed</exception>
    private static ValueTask<PooledArray<byte>> CompressData(ReadOnlySpan<byte> data, out int compressedSize, CancellationToken token)
    {
        // Check for cancellation
        if (token.IsCancellationRequested)
        {
            compressedSize = 0;
            return ValueTask.FromCanceled<PooledArray<byte>>(token);
        }

        // Get max compressed size buffer
        PooledArray<byte> compressed = new(BrotliEncoder.GetMaxCompressedLength(data.Length) + sizeof(int));

        // Compress file
        if (!BrotliEncoder.TryCompress(data, compressed.AsSpan[sizeof(int)..], out compressedSize))
        {
            // In case of error, dispose buffer
            compressed.Dispose();
            compressedSize = 0;
            return ValueTask.FromException<PooledArray<byte>>(new InvalidOperationException("Could not decompress data correctly"));
        }

        // Write original file size to header
        compressedSize += sizeof(int);
        BinaryPrimitives.WriteInt32LittleEndian(compressed.AsSpan, data.Length);
        return ValueTask.FromResult(compressed);
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
