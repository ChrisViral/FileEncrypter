using System.Security.Cryptography;
using System.Text;
using DotMake.CommandLine;
using Microsoft.Extensions.Logging;

namespace FileEncrypter;

[CliCommand(Description = "Protects files by encrypting them with a Windows User specific key.")]
public sealed class ProtectorCommand(ILogger<Protector> logger) : ICliRunAsyncWithContextAndReturn
{
    [CliArgument(Description = "The files or folders to protect",
                 Arity = CliArgumentArity.OneOrMore, ValidationRules = CliValidationRules.ExistingFileOrDirectory)]
    public FileSystemInfo[] Targets { get; set; } = [];

    [CliOption(Description = "The password to protect the files with",
               Arity = CliArgumentArity.ZeroOrOne, Required = false, Alias = "-p")]
    public string? Password { get; set; }

    [CliOption(Description = "Type of protections to allow applying",
               Arity = CliArgumentArity.ZeroOrOne, AllowedValues = ["encrypt", "decrypt", "all"], Alias = "-m")]
    public ProtectionModes Modes { get; set; } = ProtectionModes.All;

    [CliOption(Description = "Search pattern when protecting folders (supports wildcards)",
               Arity = CliArgumentArity.ZeroOrOne, Alias = "-sp")]
    public string SearchPattern { get; set; } = "*";

    [CliOption(Description = "Include subdirectories when protecting folders",
               Arity = CliArgumentArity.ZeroOrOne, Name = "--search-option", Alias = "-so")]
    public SearchOption SearchOption { get; set; } = SearchOption.TopDirectoryOnly;

    [CliOption(Description = "Protection scope for the files",
               Arity = CliArgumentArity.ZeroOrOne, Alias = "-sc")]
    public DataProtectionScope Scope { get; set; } = DataProtectionScope.CurrentUser;

    [CliOption(Description = "If files should be compressed before being encrypted",
               Arity = CliArgumentArity.ZeroOrOne, Alias = "-nc")]
    public bool NoCompression { get; set; }

    [CliOption(Description = "If old files should be kept after being processed",
               Arity = CliArgumentArity.ZeroOrOne, Alias = "-kf")]
    public bool KeepFiles { get; set; }

    [CliOption(Description = "The timeout for individual file encryption/decryption, in ms (-1 means no timeout)",
               Arity = CliArgumentArity.ZeroOrOne, Alias = "-t")]
    public int Timeout { get; set; } = -1;

    /// <inheritdoc />
    public async Task<int> RunAsync(CliContext cliContext)
    {
        byte[]? passwordBytes = !string.IsNullOrEmpty(this.Password) ? Encoding.UTF8.GetBytes(this.Password) : null;
        ProtectionOptions options = new(passwordBytes, this.Modes, this.SearchPattern, this.SearchOption, this.Scope, !this.NoCompression, !this.KeepFiles, this.Timeout);
        using Protector protector = new(logger, options);
        bool success = await protector.ProtectAll(this.Targets).ConfigureAwait(false);
        return success ? 0 : 1;
    }
}
