# hibp-passwords-downloader

A Go downloader for the [Have I Been Pwned Pwned Passwords](https://haveibeenpwned.com/Passwords) hash ranges. It can download SHA-1 or NTLM ranges either as one file per range or merged into a single text file.

## Installation

Download the latest version from the [releases page](https://github.com/ralscha/hibp-passwords-downloader/releases/latest).

## Usage

Linux/macOS:

```sh
./hibp-passwords-downloader [flags] [outputFileOrFolder]
```

Windows:

```powershell
hibp-passwords-downloader.exe [flags] [outputFileOrFolder]
```

If `outputFileOrFolder` is omitted, the downloader writes range files into `hibp-passwords`. With `--single`, it writes `hibp-passwords.txt`.

## Flags

| Flag | Shorthand | Default | Description |
| --- | --- | --- | --- |
| `--parallelism` | `-p` | `8 * CPU cores`, capped at `64` | Number of parallel range requests. Values above `64` are capped. Use `0` for the default. |
| `--overwrite` | `-o` | `false` | Overwrite existing output files while writing results. |
| `--single` | `-s` | `false` | Merge all ranges into a single `.txt` file. Without this flag, ranges are stored as individual files in a folder. |
| `--ntlm` | `-n` | `false` | Fetch NTLM hashes instead of SHA-1 hashes. |
| `--resume` | `-r` | `false` | Resume a previous download by skipping existing non-empty range files. |
| `--version` | | | Print the binary version. |
| `--help` | `-h` | | Print help. |

## Examples

Download all SHA-1 hashes to individual range files in the `pwnd` directory:

```sh
./hibp-passwords-downloader pwnd
```

Download all SHA-1 hashes to a single text file:

```sh
./hibp-passwords-downloader -s pwnedpasswords.txt
```

Download all NTLM hashes to a single text file:

```sh
./hibp-passwords-downloader -n -s pwnedpasswords_ntlm.txt
```

Resume an interrupted folder download:

```sh
./hibp-passwords-downloader -r pwnd
```

## Building from source

You need [Go](https://go.dev/), [GoReleaser](https://goreleaser.com/), and [Task](https://taskfile.dev/) installed.

```sh
git clone https://github.com/ralscha/hibp-passwords-downloader.git
cd hibp-passwords-downloader
task build
```

For a simple local build without GoReleaser:

```sh
go build ./...
```
