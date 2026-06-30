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
                case ENCRYPTED_EXTENSION when this.options.ValidModes.HasFlagFast(ProtectionModes.Decrypt):
                    data      = ProtectedData.Unprotect(data, this.options.Password, DataProtectionScope.CurrentUser);
                    finalPath = Path.ChangeExtension(file.FullName, null);
                    break;

                case ENCRYPTED_EXTENSION:
                    LogEncryptionNotEnabledIgnoringFileFilename(this.Logger, file.FullName);
                    return false;

                case not null when this.options.ValidModes.HasFlagFast(ProtectionModes.Encrypt):
                    data      = ProtectedData.Protect(data, this.options.Password, DataProtectionScope.CurrentUser);
                    finalPath = file.FullName + ENCRYPTED_EXTENSION;
                    break;

                default:
                    LogDecryptionNotEnabledIgnoringFileFilename(this.Logger, file.FullName);
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
            LogErrorHappenedForFileFilename(this.Logger, file.FullName, e);
            return false;
        }
    }
}
