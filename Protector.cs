using System.Security.Cryptography;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;

namespace FileEncrypter;

[PublicAPI]
public sealed class Protector(ILogger<Protector> logger) : IDisposable
{
    private const string ENCRYPTED_EXTENSION = ".enc";

    private readonly CancellationTokenSource source = new();

    private ILogger Logger { get; } = logger;

    public void Dispose() => this.source.Dispose();

    public async Task<bool> ProtectAll(FileSystemInfo[] targets, ProtectionOptions options)
    {
        bool success = true;
        foreach (FileSystemInfo target in targets)
        {
            switch (target)
            {
                case FileInfo file:
                    this.source.CancelAfter(options.FileTimeout);
                    success &= await ProtectFile(file, options, this.source.Token).ConfigureAwait(false);
                    this.source.TryReset();
                    break;

                case DirectoryInfo directory:
                    success &= await ProtectDirectory(directory, options).ConfigureAwait(false);
                    break;

                default:
                    this.Logger.LogError("Unidentified FileSystemInfo object ({TypeName}: {Target})", target.GetType().FullName, target);
                    success = false;
                    break;
            }
        }
        return success;
    }

    public async Task<bool> ProtectDirectory(DirectoryInfo directory, ProtectionOptions options)
    {
        bool noErrors = true;
        foreach (FileInfo file in directory.EnumerateFiles(options.SearchPattern, options.SearchOption))
        {
            this.source.CancelAfter(options.FileTimeout);
            noErrors &= await ProtectFile(file, options, this.source.Token).ConfigureAwait(false);
            this.source.TryReset();
        }
        return noErrors;
    }

    public async Task<bool> ProtectFile(FileInfo file, ProtectionOptions options, CancellationToken token)
    {
        this.Logger.LogInformation("{Action} file {FileName}.", file.Extension is ENCRYPTED_EXTENSION ? "Decrypting" : "Encrypting", file.FullName);

        try
        {
            // Open and read file
            int length = (int)file.Length;
            byte[] data = new byte[length];
            await using (FileStream readStream = file.OpenRead())
            {
                int read = await readStream.ReadAsync(data, token).ConfigureAwait(false);
                if (read < length)
                {
                    this.Logger.LogError("File could not be fully loaded into memory.");
                    return false;
                }
            }

            string finalPath;
            switch (file.Extension)
            {
                case ENCRYPTED_EXTENSION when options.ValidModes.HasFlagFast(ProtectionModes.Decrypt):
                    data      = ProtectedData.Unprotect(data, options.Password, DataProtectionScope.CurrentUser);
                    finalPath = Path.ChangeExtension(file.FullName, null);
                    break;

                case ENCRYPTED_EXTENSION:
                    this.Logger.LogWarning("Encryption not enabled, ignoring file {FileName}.", file.FullName);
                    return false;

                case not null when options.ValidModes.HasFlagFast(ProtectionModes.Encrypt):
                    data      = ProtectedData.Protect(data, options.Password, DataProtectionScope.CurrentUser);
                    finalPath = file.FullName + ENCRYPTED_EXTENSION;
                    break;

                default:
                    this.Logger.LogWarning("Decryption not enabled, ignoring file {FileName}.", file.FullName);
                    return false;
            }

            //Save the file
            await using FileStream writeStream = File.Create(finalPath);
            await writeStream.WriteAsync(data, token).ConfigureAwait(false);

            //Delete the old file
            file.Delete();
            return true;
        }
        catch (Exception e)
        {
            //Log any exceptions
            this.Logger.LogError(e, "Error happened for file {FileName}", file.FullName);
            return false;
        }
    }
}
