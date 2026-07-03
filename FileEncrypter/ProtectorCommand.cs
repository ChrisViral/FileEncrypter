using System.Security.Cryptography;
using System.Text;
using CSharpFunctionalExtensions;
using DotMake.CommandLine;
using Microsoft.Extensions.Logging;

namespace FileEncrypter;

/// <summary>
/// Protects files by encrypting them with a Windows User specific key.
/// </summary>
/// <param name="logger">Logger instance</param>
[CliCommand(Description = "Protects files by encrypting them with a Windows User specific key.")]
public sealed class ProtectorCommand(ILogger<Protector> logger) : ICliRunAsyncWithContextAndReturn
{
    /// <summary>
    /// The files or folders to protect
    /// </summary>
    [CliArgument(Description = "The files or folders to protect",
                 Arity = CliArgumentArity.OneOrMore, ValidationRules = CliValidationRules.ExistingFileOrDirectory)]
    public FileSystemInfo[] Targets { get; set; } = [];

    /// <summary>
    /// The password to protect the files with
    /// </summary>
    [CliOption(Description = "The password to protect the files with",
               Arity = CliArgumentArity.ZeroOrOne, Required = false, Alias = "-p")]
    public string? Password { get; set; }

    /// <summary>
    /// The encrypted file extension
    /// </summary>
    [CliOption(Description = "The encrypted file extension",
               Arity = CliArgumentArity.ZeroOrOne, Required = false, Alias = "-e")]
    public string EncryptedExtension { get; set; } = ".enc";

    /// <summary>
    /// Type of protections to allow applying
    /// </summary>
    [CliOption(Description = "Type of protections to allow applying",
               Arity = CliArgumentArity.ZeroOrOne, AllowedValues = ["encrypt", "decrypt", "all"], Alias = "-m")]
    public ProtectionModes Modes { get; set; } = ProtectionModes.All;

    /// <summary>
    /// Search pattern when protecting folders (supports wildcards)
    /// </summary>
    [CliOption(Description = "Search pattern when protecting folders (supports wildcards)",
               Arity = CliArgumentArity.ZeroOrOne, Alias = "-sp")]
    public string SearchPattern { get; set; } = "*";

    /// <summary>
    /// Whether to include subdirectories when protecting folders"
    /// </summary>
    [CliOption(Description = "Whether to include subdirectories when protecting folders",
               Arity = CliArgumentArity.ZeroOrOne, Name = "--search-option", Alias = "-so")]
    public SearchOption SearchOption { get; set; } = SearchOption.TopDirectoryOnly;

    /// <summary>
    /// Protection scope for the files
    /// </summary>
    [CliOption(Description = "Protection scope for the files",
               Arity = CliArgumentArity.ZeroOrOne, Alias = "-sc")]
    public DataProtectionScope Scope { get; set; } = DataProtectionScope.CurrentUser;

    /// <summary>
    /// If file compression before encryption should be omitted
    /// </summary>
    [CliOption(Description = "If file compression before encryption should be omitted",
               Arity = CliArgumentArity.ZeroOrOne, Alias = "-nc")]
    public bool NoCompression { get; set; }

    /// <summary>
    /// If old files should be kept after being processed
    /// </summary>
    [CliOption(Description = "If old files should be kept after being processed",
               Arity = CliArgumentArity.ZeroOrOne, Alias = "-kf")]
    public bool KeepFiles { get; set; }

    /// <summary>
    /// The timeout for individual file encryption/decryption, in ms (-1 for no timeout)
    /// </summary>
    [CliOption(Description = "The timeout for individual file encryption/decryption, in ms (-1 for no timeout)",
               Arity = CliArgumentArity.ZeroOrOne, Alias = "-t")]
    public int Timeout { get; set; } = -1;

    /// <inheritdoc />
    public async Task<int> RunAsync(CliContext cliContext)
    {
        byte[]? passwordBytes = !string.IsNullOrEmpty(this.Password) ? Encoding.UTF8.GetBytes(this.Password) : null;
        ProtectionOptions options = new(passwordBytes, this.EncryptedExtension, this.Modes, this.SearchPattern, this.SearchOption, this.Scope, !this.NoCompression, !this.KeepFiles, this.Timeout);
        using Protector protector = new(logger, options);
        Result result = await protector.ProtectAll(this.Targets).ConfigureAwait(false);
        return result.Match(() => 0, _ => 1);
    }
}
