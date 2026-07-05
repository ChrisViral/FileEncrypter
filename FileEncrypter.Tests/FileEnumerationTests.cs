using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;

namespace FileEncrypter.Tests;

public class FileEnumerationTests
{
    [Fact]
    public async Task GetFilesToProtect_WithDirectory_EnumeratesAllMatchingFiles_AllDirectories()
    {
        // Arrange – create nested structure: root/dir1/fileA.txt, dir2/fileB.log, dir3/sub/fileC.txt
        using TempDirectory tempDir = new();
        Directory.CreateDirectory(Path.Combine(tempDir.DirectoryPath, "dir1"));
        Directory.CreateDirectory(Path.Combine(tempDir.DirectoryPath, "dir2"));
        string subDir = Path.Combine(tempDir.DirectoryPath, "dir3", "sub");
        Directory.CreateDirectory(subDir);

        string fileAPath = Path.Combine(tempDir.DirectoryPath, "dir1", "fileA.txt");
        string fileBPath = Path.Combine(tempDir.DirectoryPath, "dir2", "fileB.log");
        string fileCPath = Path.Combine(subDir, "fileC.txt");

        await File.WriteAllBytesAsync(fileAPath, "a"u8.ToArray());
        await File.WriteAllBytesAsync(fileBPath, "b"u8.ToArray());
        await File.WriteAllBytesAsync(fileCPath, "c"u8.ToArray());

        ProtectionOptions options = new(SearchPattern: "*.txt", SearchOption: SearchOption.AllDirectories);
        Protector protector = new(NullLogger<Protector>.Instance, options);

        // Act – enumerate files via GetFilesToProtect
        FileSystemInfo[] targetInfos = [tempDir.DirectoryInfo];
        string[] enumerated = protector.GetFilesToProtect(targetInfos.AsMemory())
                                       .Where(f => f != null)
                                       .Select(fi => fi!.FullName)
                                       .OrderBy(p => p)
                                       .ToArray();

        // Assert – all .txt files in any subfolder should be present
        enumerated.Should().Contain(fileAPath);
        enumerated.Should().Contain(fileCPath);
        enumerated.Should().NotContain(fileBPath); // log file shouldn't match pattern
    }

    [Fact]
    public async Task GetFilesToProtect_WithDirectory_TopDirectoryOnly()
    {
        // Arrange – create files at root and subfolder
        using TempDirectory tempDir = new();
        Directory.CreateDirectory(Path.Combine(tempDir.DirectoryPath, "sub"));

        string fileRootPath = Path.Combine(tempDir.DirectoryPath, "root.txt");
        string fileSubPath = Path.Combine(tempDir.DirectoryPath, "sub", "child.txt");

        await File.WriteAllBytesAsync(fileRootPath, "root"u8.ToArray());
        await File.WriteAllBytesAsync(fileSubPath, "child"u8.ToArray());

        ProtectionOptions options = new(SearchPattern: "*.txt", SearchOption: SearchOption.TopDirectoryOnly);
        Protector protector = new(NullLogger<Protector>.Instance, options);

        FileSystemInfo[] targetInfos = [tempDir.DirectoryInfo];
        string[] enumerated = protector.GetFilesToProtect(targetInfos.AsMemory())
                                       .Where(f => f != null)
                                       .Select(fi => fi!.FullName)
                                       .OrderBy(p => p)
                                       .ToArray();

        // Assert – only root-level .txt should be returned
        enumerated.Should().Contain(fileRootPath);
        enumerated.Should().NotContain(fileSubPath);
    }
}
