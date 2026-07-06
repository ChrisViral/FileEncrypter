# FileEncrypter

> A lightweight command‑line tool that encrypts/decrypts files using the Windows Data Protection API (DPAPI).
> It supports custom extensions, compression, mode restrictions and a handful of other useful flags.

---

## Prerequisites

* **.NET SDK 10** – The project targets `net10.0`, which can be found [here](https://dotnet.microsoft.com/download/dotnet/10.0).

---

## How it works

The tool relies on Windows DPAPI via `System.Security.Cryptography.ProtectedData`.
The data is protected with an optional password, scoped to either the Windows user, or the machine.
Only the same user or machine can subsequently decrypt it.

Compression is applied before encryption so that even large files get a smaller footprint on disk.
By default the tool uses *Brotli* compression.

---

## Installation

Since this tool uses DPAPI, it can only be used on Windows.

You can install the tool globally via the NuGet registry or locally from a built package.

### Global install (NuGet)
```bash
dotnet tool install --global FileEncrypter
```

### Local install (built package)
If you prefer to use a local copy or test a development build:
```bash
dotnet pack --configuration Release
dotnet tool install --global --add-source ./bin/Release/FileEncrypter.nupkgs FileEncrypter
```

---

## Usage

```bash
fencrypt <targets>... [options]
```

### Arguments
| Argument    | Description                                                                                                                                 |
|-------------|---------------------------------------------------------------------------------------------------------------------------------------------|
| **targets** | One or more paths to files or directories you want to protect. Directories are processed according to the search pattern and options below. |

### Options
| Flag               | Alias       | Value                                           | Default            | Description                                                                                            |
|--------------------|-------------|-------------------------------------------------|--------------------|--------------------------------------------------------------------------------------------------------|
| `--password`       | `-p`        | string                                          | `null`             | Adds password protection while encrypting. The password must be passed again when decrypting.          |
| `--mode`           | `-m`        | `encrypt` / `decrypt` / `all`                   | `all`              | Enables the specified operations. When only one mode is allowed, files for the other mode are ignored. |
| `--extension`      | `-e`        | string                                          | `.enc`             | The extension used for encrypted files. The leading period is required.                                |
| `--search-pattern` | `-sp`       | glob (e.g., `*.txt`)                            | `*`                | When a directory is given, only files matching this pattern are considered.                            |
| `--search-option`  | `-so`       | `TopDirectoryOnly` / `AllDirectories`           | `TopDirectoryOnly` | Whether to recurse into sub‑folders when enumerating directories.                                      |
| `--scope`          | `-sc`       | `CurrentUser` / `LocalMachine`                  | `CurrentUser`      | DPAPI scope: whether the file is locked to this Windows user, or to the machine itself.                |
| `--compression`    | `-c`        | `None` / `Brotli` / `Deflate` / `GZip` / `ZLib` | `Brotli`           | Compression algorithm applied before encryption. `None` does not compress the files at all.            |
| `--keep-files`     | `-kf`       |                                                 |                    | If passed, original files are kept after encrypting/decrypting; if false they’re deleted .             |
| `--timeout`        | `-t`        | integer (milliseconds)                          | `-1`               | Per‑file operation timeout, in milliseconds.                                                           |
| `--help`           | `-h` / `-?` |                                                 |                    | Shows the command help message.                                                                        |
| `--version`        | `-v`        |                                                 |                    | Shows the tool version.                                                                                |

### Examples
```bash
# Encrypt a single file
fencrypt myfile.txt

# Decrypt an encrypted file
fencrypt myfile.txt.enc

# Bulk‑encrypt all files in a folder recursively, keep originals. Files to decrypt are ignored.
fencrypt ./MyFolder --mode encrypt --search-option AllDirectories --keep-files

# Bulk‑decrypt all *.txt.enc files in a folder recursively.
fencrypt ./MyFolder --search-option AllDirectories --search-pattern *.txt.enc

# Encrypt with a custom extension and a password at the machine scope (all users of the machine with the password can decrypt it)
fencrypt myfile.txt --extension .myenc --password MySecretPassword --scope LocalMachine
```
