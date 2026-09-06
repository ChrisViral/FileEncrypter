using FileEncrypter.Tests.Utils;
using FluentAssertions;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging.Abstractions;

namespace FileEncrypter.Tests;

[UsedImplicitly]
public sealed class FileEnumerationFixture : IDisposable
{
    private const int SUBDIR_COUNT = 5;
    public const string LOG_EXTENSION = ".log";

    internal TempDirectory TempDirectory { get; } = new();
    public List<FileInfo> TopFiles { get; } = [];
    public List<FileInfo> TextFiles { get; } = [];
    public List<FileInfo> LogFiles { get; } = [];
    public List<FileInfo> AllFiles { get; } = [];

    public FileEnumerationFixture()
    {
        // Create text files
        DirectoryInfo tempDir = this.TempDirectory.DirectoryInfo;
        for (int i = 0; i < SUBDIR_COUNT; i++)
        {
            DirectoryInfo subDir = tempDir.CreateSubdirectory($"temp{i}");
            FileInfo textFile = new(Path.Combine(subDir.FullName, TestUtils.FILE_NAME));
            File.WriteAllBytes(textFile.FullName, TestUtils.FileDataBytes);
            this.TextFiles.Add(textFile);
        }

        // Create log files
        // ReSharper disable once ForeachCanBePartlyConvertedToQueryUsingAnotherGetEnumerator
        foreach (FileInfo textFile in this.TextFiles)
        {
            FileInfo logFile = new(Path.ChangeExtension(textFile.FullName, LOG_EXTENSION));
            File.WriteAllBytes(logFile.FullName, TestUtils.FileDataBytes);
            this.LogFiles.Add(logFile);
        }

        // Create top level text file
        FileInfo topFile = this.TempDirectory.OriginalFile;
        File.WriteAllBytes(topFile.FullName, TestUtils.FileDataBytes);
        this.TopFiles.Add(topFile);
        this.TextFiles.Add(topFile);

        // Create top level log file
        FileInfo topLogFile = new(Path.ChangeExtension(topFile.FullName, LOG_EXTENSION));
        File.WriteAllBytes(topLogFile.FullName, TestUtils.FileDataBytes);
        this.TopFiles.Add(topLogFile);
        this.LogFiles.Add(topLogFile);

        // Setup all files list
        this.AllFiles.AddRange(this.TextFiles);
        this.AllFiles.AddRange(this.LogFiles);

        // Sort lists
        Comparison<FileInfo> comparer = (a, b) => string.Compare(a.FullName, b.FullName, StringComparison.Ordinal);
        this.TopFiles.Sort(comparer);
        this.TextFiles.Sort(comparer);
        this.LogFiles.Sort(comparer);
        this.AllFiles.Sort(comparer);
    }

    /// <inheritdoc />
    public void Dispose() => this.TempDirectory.Dispose();
}

public sealed class FileEnumerationTests(FileEnumerationFixture fixture) : IClassFixture<FileEnumerationFixture>
{
    private readonly FileEnumerationFixture fixture = fixture;

    [Fact]
    public void GetFilesToProtect_AllDirectories_FindsSubfiles()
    {
        // Setup data
        ProtectionOptions options = new(SearchOption: SearchOption.AllDirectories);
        Protector protector = new(NullLogger<Protector>.Instance, options);

        // Get enumerated files
        FileSystemInfo[] targets = [this.fixture.TempDirectory.DirectoryInfo];
        FileInfo?[] filesFound = [..protector.GetFilesToProtect(targets.AsMemory())];

        // Make sure all is as expected
        filesFound.ContainsAny(null).Should().BeFalse();
        filesFound.Length.Should().Be(this.fixture.AllFiles.Count);
        filesFound.OrderBy(f => f!.FullName, StringComparer.Ordinal)
                  .Should().BeEqualTo(this.fixture.AllFiles, (a, b) => string.Equals(a!.FullName, b.FullName, StringComparison.Ordinal));
    }

    [Fact]
    public void GetFilesToProtect_TopDirectoryOnly_OnlyFindsTopFiles()
    {
        // Setup data
        ProtectionOptions options = new(SearchOption: SearchOption.TopDirectoryOnly);
        Protector protector = new(NullLogger<Protector>.Instance, options);

        // Get enumerated files
        FileSystemInfo[] targets = [this.fixture.TempDirectory.DirectoryInfo];
        FileInfo?[] filesFound = [..protector.GetFilesToProtect(targets.AsMemory())];

        // Make sure all is as expected
        filesFound.ContainsAny(null).Should().BeFalse();
        filesFound.Length.Should().Be(this.fixture.TopFiles.Count);
        filesFound.OrderBy(f => f!.FullName, StringComparer.Ordinal)
                  .Should().BeEqualTo(this.fixture.TopFiles, (a, b) => string.Equals(a!.FullName, b.FullName, StringComparison.Ordinal));
    }

    [Fact]
    public void GetFilesToProtect_WithTextPattern_FindsAllMatches() => GetFilesToProtect_WithData_FindsAllMatches(TestUtils.FILE_EXTENSION, this.fixture.TextFiles);

    [Fact]
    public void GetFilesToProtect_WithLogPattern_FindsAllMatches() => GetFilesToProtect_WithData_FindsAllMatches(FileEnumerationFixture.LOG_EXTENSION, this.fixture.LogFiles);

    private void GetFilesToProtect_WithData_FindsAllMatches(string extension, List<FileInfo> files)
    {
        // Setup data
        ProtectionOptions options = new(SearchPattern: $"*{extension}", SearchOption: SearchOption.AllDirectories);
        Protector protector = new(NullLogger<Protector>.Instance, options);

        // Get enumerated files
        FileSystemInfo[] targets = [this.fixture.TempDirectory.DirectoryInfo];
        FileInfo?[] filesFound = [..protector.GetFilesToProtect(targets.AsMemory())];

        // Make sure all is as expected
        filesFound.ContainsAny(null).Should().BeFalse();
        filesFound.Length.Should().Be(files.Count);
        filesFound.OrderBy(f => f!.FullName, StringComparer.Ordinal)
                  .Should().BeEqualTo(files, (a, b) => string.Equals(a!.FullName, b.FullName, StringComparison.Ordinal));
    }
}
