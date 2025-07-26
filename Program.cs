using System.CommandLine;
using System.Text;
using FileEncrypter;

RootCommand root = new("FileEncrypter")
{
    Description = "Protects files by encrypting them with a Windows User specific key."
};

Argument<FileSystemInfo[]> targetsArgument = new("targets")
{
    Description = "The files or folders to protect",
    Arity       = ArgumentArity.OneOrMore
};
targetsArgument.AcceptExistingOnly();

Option<string?> passwordOption = new("--password", "-p")
{
    Description = "The password to protect the files with",
    Arity       = ArgumentArity.ZeroOrOne
};

Option<bool> noEncryptOption = new("--no-encrypt")
{
    Description = "Prevent files from being encrypted",
    Arity       = ArgumentArity.ZeroOrOne
};

Option<bool> noDecryptOption = new("--no-decrypt")
{
    Description = "Prevents files from being decrypted",
    Arity       = ArgumentArity.ZeroOrOne
};

Option<string> searchPatternOption = new("--search", "-s")
{
    Description         = "Search pattern when protecting folders (supports wildcards)",
    Arity               = ArgumentArity.ZeroOrOne,
    DefaultValueFactory = _ => "*"
};

Option<bool> includeSubdirectoriesOption = new("--include-subdirectories")
{
    Description = "Include subdirectories when protecting folders",
    Arity       = ArgumentArity.ZeroOrOne
};

root.Arguments.Add(targetsArgument);
root.Options.Add(passwordOption);
root.Options.Add(noEncryptOption);
root.Options.Add(noDecryptOption);
root.Options.Add(searchPatternOption);
root.Options.Add(includeSubdirectoriesOption);

root.SetAction(async (result, _) =>
{
    FileSystemInfo[] targets   = result.GetRequiredValue(targetsArgument);
    string? password           = result.GetValue(passwordOption);
    bool noEncrypt             = result.GetValue(noEncryptOption);
    bool noDecrypt             = result.GetValue(noDecryptOption);
    string searchPattern       = result.GetRequiredValue(searchPatternOption);
    bool includeSubdirectories = result.GetValue(includeSubdirectoriesOption);

    byte[]? passwordBytes = !string.IsNullOrEmpty(password) ? Encoding.UTF8.GetBytes(password) : null;
    ProtectionModes modes = ProtectionModes.ALL;
    if (noEncrypt)
    {
        modes ^= ProtectionModes.ENCRYPT;
    }
    if (noDecrypt)
    {
        modes ^= ProtectionModes.DECRYPT;
    }
    SearchOption searchOption = includeSubdirectories ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;
    ProtectionOptions options = new(passwordBytes, modes, searchPattern, searchOption);

    using Protector protector = new(options);
    bool noErrors = await protector.ProtectAll(targets).ConfigureAwait(false);
    return noErrors ? 0 : 1;
});

int exitCode = await root.Parse(args).InvokeAsync().ConfigureAwait(false);
#if !DEBUG
if (exitCode is not 0)
{
    await Console.Out.WriteLineAsync("Press any key to continue...").ConfigureAwait(false);
    Console.ReadKey(true);
}
#endif

return exitCode;
