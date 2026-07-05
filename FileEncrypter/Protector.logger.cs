using System;
using System.IO;
using Microsoft.Extensions.Logging;

namespace FileEncrypter;

public partial class Protector
{
    [LoggerMessage(LogLevel.Information, "{Action} file {FileName}.")]
    static partial void LogActionFileFilename(ILogger logger, string action, string fileName);

    [LoggerMessage(LogLevel.Error, "Unidentified FileSystemInfo object ({TypeName}: {Target})")]
    static partial void LogUnidentifiedFilesysteminfoObjectTypenameTarget(ILogger logger, string typeName, FileSystemInfo target);

    [LoggerMessage(LogLevel.Warning, "Encryption not enabled, ignoring file {FileName}.")]
    static partial void LogEncryptionNotEnabledIgnoringFileFilename(ILogger logger, string fileName);

    [LoggerMessage(LogLevel.Warning, "Decryption not enabled, ignoring file {FileName}.")]
    static partial void LogDecryptionNotEnabledIgnoringFileFilename(ILogger logger, string fileName);

    [LoggerMessage(LogLevel.Error, "Error happened for file {FileName}")]
    static partial void LogErrorHappenedForFileFilename(ILogger logger, string fileName, Exception exception);

    [LoggerMessage(LogLevel.Error, "File {FileName} too large to handle.")]
    static partial void LogFileFilenameTooLargeToHandle(ILogger logger, string fileName);
}
