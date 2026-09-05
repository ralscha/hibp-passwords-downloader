# hibp-passwords-downloader

A Go downloader for the [Have I Been Pwned Pwned Passwords](https://haveibeenpwned.com/Passwords) hash ranges. It can download SHA-1 or NTLM ranges either as one file per range or merged into a single text file.

Range files are named after their five-character prefix and contain the suffixes returned by the API. A merged file restores each prefix and contains complete hashes in `HASH:COUNT` format.

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

Requests use the standard `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY` environment variables. Transient failures are retried, including the delay supplied by a `Retry-After` response header.

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

Press Ctrl+C to stop cleanly. Every completed range is retained, so the same command can be restarted with `--resume`. In single-file mode, resumable ranges are kept in a hidden sibling folder until the final file has been merged successfully:

```sh
./hibp-passwords-downloader -s -r pwnedpasswords.txt
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

## Releasing

Create and push a version tag such as `v1.1.0`. The release workflow runs the tests, builds Linux, Windows, and macOS archives with GoReleaser, and publishes them with a checksum file on the corresponding GitHub release.

```sh
task release-tag TAG=v1.1.0
```

Use `task tag TAG=v1.1.0` and `task push-tag TAG=v1.1.0` when you want to create and push the tag separately. Run `task snapshot` to build the complete release matrix locally without publishing it.
