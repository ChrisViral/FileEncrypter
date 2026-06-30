using System.Text;
using DotMake.CommandLine;

namespace FileEncrypter;

[CliCommand(Description = "Protects files by encrypting them with a Windows User specific key.")]
public sealed class ProtectorCommand(Protector protector) : ICliRunAsyncWithContextAndReturn
{
    private Protector Protector { get; } = protector;

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
               Arity = CliArgumentArity.ZeroOrOne, Alias = "-s")]
    public string SearchPattern { get; set; } = "*";

    [CliOption(Description = "Include subdirectories when protecting folders",
               Arity = CliArgumentArity.ZeroOrOne)]
    public SearchOption SearchOption { get; set; } = SearchOption.TopDirectoryOnly;

    /// <inheritdoc />
    public async Task<int> RunAsync(CliContext cliContext)
    {
        byte[]? passwordBytes = !string.IsNullOrEmpty(this.Password) ? Encoding.UTF8.GetBytes(this.Password) : null;
        ProtectionOptions options = new(passwordBytes, this.Modes, this.SearchPattern, this.SearchOption);
        bool success = await this.Protector.ProtectAll(this.Targets, options).ConfigureAwait(false);
        return success ? 0 : 1;
    }
}
