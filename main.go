package main

import (
	"fmt"
	"github.com/alitto/pond"
	"github.com/andybalholm/brotli"
	"github.com/avast/retry-go"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

const (
	hibpURL = "https://api.pwnedpasswords.com/range/"
)

type Statistics struct {
	HashesDownloaded           uint64
	CloudflareRequests         uint64
	CloudflareHits             uint64
	CloudflareMisses           uint64
	CloudflareRequestTimeTotal uint64
}

type PwnedPasswordsDownloader struct {
	Statistics         Statistics
	Client             *http.Client
	OutputFileOrFolder string
	DownloadFolder     string
	Parallelism        int
	Overwrite          bool
	Resume             bool
	SingleFile         bool
	FetchNtlm          bool
}

func main() {
	var ppd PwnedPasswordsDownloader
	cmd := &cobra.Command{
		Use:   "hibp-passwords-downloader [outputFileOrFolder]",
		Short: "Downloads Have I Been Pwned passwords hashes lists to find compromised passwords",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				ppd.OutputFileOrFolder = args[0]
			} else {
				ppd.OutputFileOrFolder = "hibp-passwords.txt"
			}
			if ppd.Parallelism == 0 {
				ppd.Parallelism = runtime.NumCPU() * 2
				if ppd.Parallelism > 8 {
					ppd.Parallelism = 8
				}
			}

			ppd.Client = &http.Client{}
			return ppd.execute()
		},
	}

	cmd.Flags().IntVarP(&ppd.Parallelism, "parallelism", "p", 0, "The number of parallel requests to make to Have I Been Pwned to download the hash ranges. If omitted, defaults to four times the number of processors on the machine. Maximum 24")
	cmd.Flags().BoolVarP(&ppd.Overwrite, "overwrite", "o", false, "When set, overwrite any existing files while writing the results. Defaults to false.")
	cmd.Flags().BoolVarP(&ppd.SingleFile, "single", "s", true, "When set, writes the hash ranges into a single .txt file. Otherwise downloads ranges to individual files into a subfolder. If ommited defaults to single file.")
	cmd.Flags().BoolVarP(&ppd.FetchNtlm, "ntlm", "n", false, "When set, fetches NTLM hashes instead of SHA1.")
	cmd.Flags().BoolVarP(&ppd.Resume, "resume", "r", false, "When individual files are used, resume download of existing files.")

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func (ppd *PwnedPasswordsDownloader) execute() error {
	if ppd.SingleFile {
		if _, err := os.Stat(ppd.OutputFileOrFolder); !os.IsNotExist(err) {
			if !ppd.Overwrite {
				return fmt.Errorf("output file %q already exists. Use -o if you want to overwrite it", ppd.OutputFileOrFolder)
			}
		}
		ppd.DownloadFolder = ppd.OutputFileOrFolder + "_" + time.Now().Format("2006-01-02_15-04-05")
		if err := os.Mkdir(ppd.DownloadFolder, os.ModePerm); err != nil {
			return err
		}
	} else {
		if _, err := os.Stat(ppd.OutputFileOrFolder); !os.IsNotExist(err) {
			containsFiles := false
			if files, err := os.ReadDir(ppd.OutputFileOrFolder); err == nil {
				containsFiles = len(files) > 0
			}
			if !ppd.Resume && !ppd.Overwrite && containsFiles {
				return fmt.Errorf("output folder %q already exists and is not empty. Use -o if you want to overwrite it", ppd.OutputFileOrFolder)
			}
		} else {
			if err := os.Mkdir(ppd.OutputFileOrFolder, os.ModePerm); err != nil {
				return err
			}
		}
		ppd.DownloadFolder = ppd.OutputFileOrFolder
	}

	max := 1024 * 1024

	bar := progressbar.Default(int64(max))
	pool := pond.New(ppd.Parallelism, max)
	for hashPrefix := 0; hashPrefix < max; hashPrefix++ {
		p := hashPrefix
		pool.Submit(func() {
			err := ppd.downloadHashes(bar, p)
			if err != nil {
				log.Fatal(err)
			}
		})
	}
	pool.StopAndWait()

	if ppd.SingleFile {
		if err := ppd.mergeFiles(); err != nil {
			return err
		}

		if err := os.RemoveAll(ppd.DownloadFolder); err != nil {
			return err
		}
	}

	err := bar.Finish()
	if err != nil {
		return err
	}

	fmt.Printf("Hashes downloaded:               %d\n", ppd.Statistics.HashesDownloaded)
	fmt.Printf("Cloudflare requests:             %d\n", ppd.Statistics.CloudflareRequests)
	fmt.Printf("Cloudflare hits:                 %d\n", ppd.Statistics.CloudflareHits)
	fmt.Printf("Cloudflare misses:               %d\n", ppd.Statistics.CloudflareMisses)
	fmt.Printf("Cloudflare hit rate:             %d %%\n", ppd.Statistics.CloudflareHits*100/ppd.Statistics.CloudflareRequests)
	fmt.Printf("Cloudflare request time total:   %d ms\n", ppd.Statistics.CloudflareRequestTimeTotal)
	fmt.Printf("Cloudflare request time average: %d ms\n", ppd.Statistics.CloudflareRequestTimeTotal/ppd.Statistics.CloudflareRequests)

	return nil
}

func (ppd *PwnedPasswordsDownloader) mergeFiles() error {
	files, err := os.ReadDir(ppd.DownloadFolder)
	if err != nil {
		return err
	}
	var fileNames []string
	for _, file := range files {
		fileNames = append(fileNames, file.Name())
	}
	sort.Strings(fileNames)

	outputFile, err := os.Create(ppd.OutputFileOrFolder)
	if err != nil {
		return err
	}
	defer outputFile.Close()

	for _, fileName := range fileNames {
		file, err := os.Open(ppd.DownloadFolder + "/" + fileName)
		if err != nil {
			return err
		}
		if _, err := io.Copy(outputFile, file); err != nil {
			return err
		}
		file.Close()

		err = os.Remove(ppd.DownloadFolder + "/" + fileName)
		if err != nil {
			return err
		}
	}

	return nil
}

func (ppd *PwnedPasswordsDownloader) downloadHashes(bar *progressbar.ProgressBar, prefix int) error {
	hexPrefix := intToHex(prefix)
	downloadFile := filepath.Join(ppd.DownloadFolder, hexPrefix+".txt")
	if ppd.Resume {
		if _, err := os.Stat(downloadFile); !os.IsNotExist(err) {
			err = bar.Add(1)
			if err != nil {
				return err
			}
			return nil
		}
	}

	url := hibpURL + hexPrefix
	if ppd.FetchNtlm {
		url += "?mode=ntlm"
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	req.Header.Set("User-Agent", "hibp-downloader")
	req.Header.Set("Accept-Encoding", "br")

	var resp *http.Response
	start := time.Now()
	err = retry.Do(
		func() error {
			var err error
			resp, err = ppd.Client.Do(req)
			return err
		},
		retry.Attempts(10),
		retry.OnRetry(func(n uint, err error) {
			log.Printf("Retrying request after error: %v", err)
		}),
	)
	atomic.AddUint64(&ppd.Statistics.CloudflareRequestTimeTotal, uint64(time.Since(start).Milliseconds()))

	if err != nil {
		return err
	}
	defer resp.Body.Close()

	cfCacheStatus := resp.Header.Get("Cf-Cache-Status")
	atomic.AddUint64(&ppd.Statistics.CloudflareRequests, 1)
	if cfCacheStatus == "HIT" {
		atomic.AddUint64(&ppd.Statistics.CloudflareHits, 1)
	} else {
		atomic.AddUint64(&ppd.Statistics.CloudflareMisses, 1)
	}

	reader := brotli.NewReader(resp.Body)
	respBody, err := io.ReadAll(reader)
	if err != nil {
		return err
	}

	splitted := strings.Split(string(respBody), "\n")
	f, err := os.Create(downloadFile)
	if err != nil {
		return err
	}
	defer f.Close()

	for _, line := range splitted {
		_, err = f.WriteString(hexPrefix + line + "\n")
		if err != nil {
			return err
		}
	}
	atomic.AddUint64(&ppd.Statistics.HashesDownloaded, uint64(len(splitted)))

	err = bar.Add(1)
	if err != nil {
		return err
	}

	return nil
}

func intToHex(i int) string {
	return strings.ToUpper(fmt.Sprintf("%05x", i))
}
