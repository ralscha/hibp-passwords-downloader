# hibp-passwords-downloader

Clone of the [official HIBP passwords downloader](https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader) written in Go. This program allows users to download the whole
HIBP passwords database.

# Installation

Download the latest version from the [releases page](https://github.com/ralscha/hibp-passwords-downloader/releases/latest).

# Usage

On Linux/macOS
```
./hibp-passwords-downloader [outputFileOrFolder]
```

On Windows
```
hibp-passwords-downloader.exe [outputFileOrFolder]
```

outputFileOrFolder: The name of the output file or folder where the downloaded files will be stored.


# Flags

| Flag        | Shorthand     | Default     | Description |
|-------------|---------------|-------------|-------------|
| parallelism  | -p | 4 * CPU cores  | The number of parallel requests to send to Have I Been Pwned to download the hash ranges. Has a maximum of 64. |
| overwrite | -o | false | When set, overwrites any existing files while writing the results. |
| single | -s | false | When set, writes the hash ranges into a single .txt file. Otherwise, downloads ranges to individual files into a subfolder. |
| ntlm | -n | false | When set, fetches NTLM hashes instead of SHA1. |
| resume | -r | false | When individual files are used, resume download. Skips already downloaded files.  |


# Usage examples

### Download all SHA1 hashes to a single text file called `pwnedpasswords.txt`
`./hibp-passwords-downloader -s pwnedpasswords.txt`

### Download all SHA1 hashes to individual text files into the `pwnd` directory.
`./hibp-passwords-downloader pwnd`

### Download all NTLM hashes to a single txt file called `pwnedpasswords_ntlm.txt`
`./hibp-passwords-downloader -n pwnedpasswords_ntlm.txt`


# Building from source
You need to have [Go](https://golang.org/), [GoReleaser](https://goreleaser.com/) and [Task](https://taskfile.dev/)
installed on your machine.

After installing the prerequisites, clone this repository locally using the following command:

```
git clone https://github.com/ralscha/hibp-passwords-downloader.git
```

Once you have cloned the repository, navigate to the directory and build it:

```
cd hibp-passwords-downloader
task build
``` 
