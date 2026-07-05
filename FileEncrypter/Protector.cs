using System.Buffers.Binary;
using System.ComponentModel;
using System.Diagnostics;
using System.IO.Compression;
using System.Numerics;
using System.Security.Cryptography;
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
    internal sealed class State
    {
        /// <summary>
        /// Failure count
        /// </summary>
        public int failures;
    }

    internal const int NONCOMPRESSED_HEADER_SIZE = sizeof(byte);
    internal const int COMPRESSED_HEADER_SIZE    = NONCOMPRESSED_HEADER_SIZE + sizeof(int);

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
    internal async Task<Result> ProtectFile(FileInfo file, CancellationToken token)
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
    internal IEnumerable<FileInfo?> GetFilesToProtect(ReadOnlyMemory<FileSystemInfo> targets)
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
    internal async ValueTask ProtectFileParallel((FileInfo?, State) fileData, CancellationToken token)
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
    internal async Task<Result> EncryptFile(FileInfo file, PooledArray<byte> data, CancellationToken token)
    {
        // Compress and then encrypt
        (PooledArray<byte> compressed, int compressedSize) = await CompressData(data.AsMemory, token).ConfigureAwait(false);
        using (compressed)
        {
            Result<(PooledArray<byte>, int)> protectResult = await ProtectData(compressed.AsMemory[..compressedSize], token).ConfigureAwait(false);
            if (protectResult.IsFailure) return protectResult.ConvertFailure();
            (PooledArray<byte> encrypted, int encryptedSize) = protectResult.Value;
            using (encrypted)
            {
                // Save encrypted file to disk
                await SaveData(encrypted.AsMemory[..encryptedSize], file.FullName + this.options.EncryptedExtension, token).ConfigureAwait(false);
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
    /// Decrypts a given file
    /// </summary>
    /// <param name="file">File to decrypt</param>
    /// <param name="data">Encrypted file data</param>
    /// <param name="token">Cancellatio token</param>
    /// <returns>True if no errors occured, otherwise false</returns>
    internal async Task<Result> DecryptFile(FileInfo file, PooledArray<byte> data, CancellationToken token)
    {
        // Decrypt file
        Result<(PooledArray<byte>, int)> unprotectResult = await UnprotectData(data.AsMemory, token).ConfigureAwait(false);
        if (unprotectResult.IsFailure) return unprotectResult.ConvertFailure();

        (PooledArray<byte> decrypted, int decryptedSize) = unprotectResult.Value;
        using (decrypted)
        {
            // Decompress file before saving
            string path = Path.ChangeExtension(file.FullName, null);
            (PooledArray<byte> decompressed, int decompressedSize) = await DecompressData(decrypted, decryptedSize, token).ConfigureAwait(false);
            using (decompressed)
            {
                await SaveData(decompressed.AsMemory[..decompressedSize], path, token).ConfigureAwait(false);
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
    internal ValueTask<Result<(PooledArray<byte> decrypted, int decryptedSize)>> UnprotectData(Memory<byte> data, CancellationToken token)
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
            this.Logger.LogError(e, "Error while decrypting data");
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
    internal ValueTask<Result<(PooledArray<byte> encrypted, int encryptedSize)>> ProtectData(Memory<byte> data, CancellationToken token)
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
    /// Compresses the given file data
    /// </summary>
    /// <param name="data">Data to compress</param>
    /// <param name="token">Cancellation token</param>
    /// <returns>A tuple containing the compressed data output, and the compressed data output size</returns>
    /// <exception cref="InvalidEnumArgumentException">If the compression option is not a valid value</exception>
    /// <exception cref="InvalidOperationException">If the data could not be compressed</exception>
    internal async Task<(PooledArray<byte> compressed, int compressedSize)> CompressData(ReadOnlyMemory<byte> data, CancellationToken token)
    {
        PooledArray<byte> compressed;
        if (this.options.Compression is CompressionOption.None)
        {
            compressed = new PooledArray<byte>(data.Length + NONCOMPRESSED_HEADER_SIZE);
            data.CopyTo(compressed.AsMemory[NONCOMPRESSED_HEADER_SIZE..]);
            compressed[0] = (byte)this.options.Compression;
            return (compressed, compressed.Length);
        }

        // Get starting buffer size
        uint bufferSize = this.options.Compression is CompressionOption.Brotli
                              ? (uint)BrotliEncoder.GetMaxCompressedLength(data.Length)
                              : (uint)(data.Length * 1.2f);
        bufferSize = (bufferSize + COMPRESSED_HEADER_SIZE + 1) / 2U;
        do
        {
            // Increase buffer size
            bufferSize = Math.Min(bufferSize * 2U, int.MaxValue);

            // Compress file
            Result<(PooledArray<byte>, int)> compressionResult = await TryCompressWithStream((int)bufferSize, this.options.Compression, data, token).ConfigureAwait(false);
            if (compressionResult.IsSuccess)
            {
                (compressed, int compressedSize) = compressionResult.Value;
                compressedSize += COMPRESSED_HEADER_SIZE;
                compressed[0] = (byte)this.options.Compression;
                BinaryPrimitives.WriteInt32LittleEndian(compressed[sizeof(byte)..], data.Length);
                return (compressed, compressedSize);
            }
        }
        while (bufferSize < int.MaxValue);

        // In case of error, dispose buffer
        throw new InvalidOperationException("Could not compress data correctly");
    }

    /// <summary>
    /// Decompresses the given file data
    /// </summary>
    /// <param name="data">Data to decompress</param>
    /// <param name="dataLength">The length of the data to decompress</param>
    /// <param name="token">Cancellation token</param>
    /// <returns>A tuple containing the decompressed data output, and the decompressed data output size</returns>
    /// <exception cref="InvalidEnumArgumentException">If the compression option is not a valid value</exception>
    /// <exception cref="InvalidOperationException">If the data could not be decompressed</exception>
    internal static async Task<(PooledArray<byte> decompressed, int decompressedSize)> DecompressData(PooledArray<byte> data, int dataLength, CancellationToken token)
    {
        int decompressedSize;
        CompressionOption compression = (CompressionOption)data[0];
        if (compression is CompressionOption.None)
        {
            decompressedSize = dataLength - NONCOMPRESSED_HEADER_SIZE;
            PooledArray<byte> decompressed = new(decompressedSize);
            data.AsSpan.Slice(NONCOMPRESSED_HEADER_SIZE, decompressedSize).CopyTo(decompressed.AsSpan);
            return (decompressed, decompressedSize);
        }

        // Get decompressed size from file header
        decompressedSize = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan.Slice(sizeof(byte), sizeof(int)));

        // Decompress file
        Result<PooledArray<byte>> decompressionResult = await TryDecompressWithStream(decompressedSize, compression, data, dataLength, token).ConfigureAwait(false);
        return decompressionResult.IsSuccess ? (decompressionResult.Value, decompressedSize) : throw new InvalidOperationException("Could not decompress data correctly");
    }

    /// <summary>
    /// Tries to compress the given data to a buffer of the specified size
    /// </summary>
    /// <param name="bufferSize">Buffer size to initialize</param>
    /// <param name="compression">Compression method</param>
    /// <param name="data">Data to compress</param>
    /// <param name="token">Cancellation token</param>
    /// <returns>A result object, if successful, contains the buffer with the compressed data, and the size of the compressed data within it</returns>
    /// <exception cref="InvalidOperationException">If trying to compress with <see cref="CompressionOption.None"/></exception>
    /// <exception cref="InvalidEnumArgumentException">For invalid values of <see cref="CompressionOption"/></exception>
    internal static async Task<Result<(PooledArray<byte> buffer, int written)>> TryCompressWithStream(int bufferSize, CompressionOption compression, ReadOnlyMemory<byte> data, CancellationToken token)
    {
        PooledArray<byte> buffer = new(bufferSize);
        try
        {
            using MemoryStream memoryStream = new(buffer.AsRawArray, COMPRESSED_HEADER_SIZE, bufferSize - COMPRESSED_HEADER_SIZE, true);
            await using Stream compressionStream = compression switch
            {
                CompressionOption.Brotli  => new BrotliStream(memoryStream, CompressionLevel.SmallestSize),
                CompressionOption.Deflate => new DeflateStream(memoryStream, CompressionLevel.SmallestSize),
                CompressionOption.GZip    => new GZipStream(memoryStream, CompressionLevel.SmallestSize),
                CompressionOption.ZLib    => new ZLibStream(memoryStream, CompressionLevel.SmallestSize),
                CompressionOption.None    => throw new InvalidOperationException("No compression stream for None compression"),
                _                         => throw new InvalidEnumArgumentException(nameof(compression), (int)compression, typeof(CompressionOption)),
            };

            await compressionStream.WriteAsync(data, token).ConfigureAwait(false);
            await compressionStream.FlushAsync(token).ConfigureAwait(false);
            return Result.Success((buffer, (int)memoryStream.Position));
        }
        catch (Exception e) when (e is InvalidOperationException or InvalidEnumArgumentException)
        {
            buffer.Dispose();
            throw;
        }
        catch
        {
            buffer.Dispose();
            return Result.Failure<(PooledArray<byte>, int)>("Failed to write to buffer");
        }
    }

    /// <summary>
    /// Tries to decompress the given data to a buffer of the specified size
    /// </summary>
    /// <param name="bufferSize">Buffer size to initialize</param>
    /// <param name="compression">Compression method</param>
    /// <param name="data">Data to decompress</param>
    /// <param name="dataLength">Length of the data in the buffer</param>
    /// <param name="token">Cancellation token</param>
    /// <returns>A result object, if successful, contains the buffer with the decompressed data</returns>
    /// <exception cref="InvalidOperationException">If trying to compress with <see cref="CompressionOption.None"/></exception>
    /// <exception cref="InvalidEnumArgumentException">For invalid values of <see cref="CompressionOption"/></exception>
    internal static async Task<Result<PooledArray<byte>>> TryDecompressWithStream(int bufferSize, CompressionOption compression, PooledArray<byte> data, int dataLength, CancellationToken token)
    {
        PooledArray<byte> buffer = new(bufferSize);
        try
        {
            using MemoryStream memoryStream = new(data.AsRawArray, COMPRESSED_HEADER_SIZE, dataLength - COMPRESSED_HEADER_SIZE, false);
            await using Stream decompressionStream = compression switch
            {
                CompressionOption.Brotli  => new BrotliStream(memoryStream, CompressionMode.Decompress),
                CompressionOption.Deflate => new DeflateStream(memoryStream, CompressionMode.Decompress),
                CompressionOption.GZip    => new GZipStream(memoryStream, CompressionMode.Decompress),
                CompressionOption.ZLib    => new ZLibStream(memoryStream, CompressionMode.Decompress),
                CompressionOption.None    => throw new InvalidOperationException("No compression stream for None compression"),
                _                         => throw new InvalidEnumArgumentException(nameof(compression), (int)compression, typeof(CompressionOption)),
            };

            await decompressionStream.ReadExactlyAsync(buffer.AsMemory, token).ConfigureAwait(false);
            return Result.Success(buffer);
        }
        catch (Exception e) when (e is InvalidOperationException or InvalidEnumArgumentException)
        {
            buffer.Dispose();
            throw;
        }
        catch
        {
            buffer.Dispose();
            return Result.Failure<PooledArray<byte>>("Failed to write to buffer");
        }
    }

    /// <summary>
    /// Saves the given file data to a file
    /// </summary>
    /// <param name="data">File data to save</param>
    /// <param name="path">Save file path</param>
    /// <param name="token">Cancellation token</param>
    internal static async Task SaveData(ReadOnlyMemory<byte> data, string path, CancellationToken token)
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
