using DotMake.CommandLine;
using FileEncrypter.Tool;
using Microsoft.Extensions.DependencyInjection;
using Serilog;

if (!OperatingSystem.IsWindows())
{
    await Console.Error.WriteLineAsync("This tool is only available on Windows due to usage of DPAPI\nPress any key to exit...").ConfigureAwait(false);
    Console.ReadKey(true);
    return 1;
}

// DI Configuration
Cli.Ext.ConfigureServices(services =>
{
    Log.Logger = new LoggerConfiguration()
                .WriteTo.Console()
                .Enrich.FromLogContext()
                .CreateLogger();

    services.AddLogging(builder =>
    {
        builder.AddSerilog(Log.Logger, true);
    });
});

// If no args passed, default to help
if (args is [])
{
    args = ["-h"];
}

int result;
try
{
    // Try running the command
    result = await Cli.RunAsync<ProtectorCommand>(args).ConfigureAwait(false);
}
catch (Exception e)
{
    // Log exceptions
    Log.Error(e, "An error occured while executing the command.");
    result = 1;
}

#if !DEBUG
if (result is not 0)
{
    await Console.Out.WriteLineAsync("Press any key to continue...").ConfigureAwait(false);
    Console.ReadKey(true);
}
#endif

return result;
