using System.Security.Cryptography;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Console;

namespace FileEncrypter;

[Flags, PublicAPI]
public enum ProtectionModes
{
    NONE    = 0b00,
    ENCRYPT = 0b01,
    DECRYPT = 0b10,
    ALL     = 0b11
}

public static class ProtectionModesExtensions
{
    public static bool HasFlagFast(this ProtectionModes value, ProtectionModes flag) => (value & flag) is not 0;
}

[PublicAPI]
public sealed class Protector : IDisposable
{
    private const string ENCRYPTED_EXTENSION = ".enc";

    private readonly ProtectionOptions options;
    private readonly int fileTimeout;
    private readonly CancellationTokenSource source = new();

    private ILogger Logger { get; }

    public Protector(in ProtectionOptions options, int fileTimeout = 1000)
    {
        this.options = options;
        using ILoggerFactory factory = LoggerFactory.Create(b => b.AddSimpleConsole(o =>
        {
            o.SingleLine      = true;
            o.TimestampFormat = "HH:mm:ss ";
            o.ColorBehavior   = LoggerColorBehavior.Enabled;
        }));
        this.Logger      = factory.CreateLogger(string.Empty);
        this.fileTimeout = fileTimeout;
    }

    public void Dispose() => this.source.Dispose();

    public async Task<bool> ProtectAll(FileSystemInfo[] targets)
    {
        bool noErrors = true;
        foreach (FileSystemInfo target in targets)
        {
            switch (target)
            {
                case FileInfo file:
                    this.source.CancelAfter(this.fileTimeout);
                    noErrors &= await ProtectFile(file, this.source.Token).ConfigureAwait(false);
                    this.source.TryReset();
                    break;

                case DirectoryInfo directory:
                    noErrors &= await ProtectDirectory(directory).ConfigureAwait(false);
                    break;

                default:
                    this.Logger.LogError("Unidentified FileSystemInfo object ({TypeName}: {Target})", target.GetType().FullName, target);
                    noErrors = false;
                    break;
            }
        }
        return noErrors;
    }

    public async Task<bool> ProtectDirectory(DirectoryInfo directory)
    {
        bool noErrors = true;
        foreach (FileInfo file in directory.EnumerateFiles(this.options.SearchPattern, this.options.SearchOption))
        {
            this.source.CancelAfter(this.fileTimeout);
            noErrors &= await ProtectFile(file, this.source.Token).ConfigureAwait(false);
            this.source.TryReset();
        }
        return noErrors;
    }

    public async Task<bool> ProtectFile(FileInfo file, CancellationToken token)
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
                case ENCRYPTED_EXTENSION when this.options.ValidModes.HasFlagFast(ProtectionModes.DECRYPT):
                    data      = ProtectedData.Unprotect(data, this.options.Password, DataProtectionScope.CurrentUser);
                    finalPath = Path.ChangeExtension(file.FullName, null);
                    break;

                case ENCRYPTED_EXTENSION:
                    this.Logger.LogWarning("Encryption not enabled, ignoring file {FileName}.", file.FullName);
                    return false;

                case not null when this.options.ValidModes.HasFlagFast(ProtectionModes.ENCRYPT):
                    data      = ProtectedData.Protect(data, this.options.Password, DataProtectionScope.CurrentUser);
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