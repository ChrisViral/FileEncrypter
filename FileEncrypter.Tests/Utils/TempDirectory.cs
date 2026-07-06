namespace FileEncrypter.Tests.Utils;

/// <summary>
/// Temporary disposable directory utility
/// </summary>
internal sealed class TempDirectory : IDisposable
{
    /// <summary>
    /// Temp directory path
    /// </summary>
    public string DirectoryPath { get; private set; }

    /// <summary>
    /// Temp directory info
    /// </summary>
    public DirectoryInfo DirectoryInfo => new(this.DirectoryPath);

    /// <summary>
    /// Creates a new unique temp directory
    /// </summary>
    public TempDirectory()
    {
        do
        {
            // Make sure path doesn't already exist
            this.DirectoryPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        }
        while (Directory.Exists(this.DirectoryPath));

        // Create directory
        Directory.CreateDirectory(this.DirectoryPath);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        // Delete directory and all it's contents
        Directory.Delete(this.DirectoryPath, true);
        this.DirectoryPath = null!;
    }
}
