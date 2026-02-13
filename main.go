package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/avast/retry-go"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
)

const (
	hibpURL = "https://api.pwnedpasswords.com/range/"
)

type Statistics struct {
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

type httpStatusError struct {
	statusCode int
}

func (e *httpStatusError) Error() string {
	return fmt.Sprintf("unexpected HTTP status: %d", e.statusCode)
}

func (e *httpStatusError) Retryable() bool {
	return e.statusCode == http.StatusTooManyRequests || e.statusCode >= http.StatusInternalServerError
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
				ppd.Parallelism = min(runtime.NumCPU()*8, 64)
			}

			ppd.Client = &http.Client{
				Timeout: 60 * time.Second,
				Transport: &http.Transport{
					MaxIdleConnsPerHost: ppd.Parallelism,
				},
			}
			return ppd.execute()
		},
	}

	cmd.Flags().IntVarP(&ppd.Parallelism, "parallelism", "p", 0, "The number of parallel requests to make to Have I Been Pwned to download the hash ranges. If omitted, defaults to eight times the number of processors on the machine. Maximum 64")
	cmd.Flags().BoolVarP(&ppd.Overwrite, "overwrite", "o", false, "When set, overwrite any existing files while writing the results. Defaults to false.")
	cmd.Flags().BoolVarP(&ppd.SingleFile, "single", "s", false, "When set, writes the hash ranges into a single .txt file. Otherwise downloads ranges to individual files into a subfolder. If omitted defaults to individual files.")
	cmd.Flags().BoolVarP(&ppd.FetchNtlm, "ntlm", "n", false, "When set, fetches NTLM hashes instead of SHA1.")
	cmd.Flags().BoolVarP(&ppd.Resume, "resume", "r", false, "When set, resumes download of existing files.")

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
		ppd.DownloadFolder = filepath.Join(filepath.Dir(ppd.OutputFileOrFolder), ".hibp_"+filepath.Base(ppd.OutputFileOrFolder))

		if _, err := os.Stat(ppd.DownloadFolder); !os.IsNotExist(err) {
			if ppd.Resume {
				fmt.Printf("resuming download of %q\n", ppd.OutputFileOrFolder)
			} else {
				if err := os.RemoveAll(ppd.DownloadFolder); err != nil {
					return err
				}
				if err := os.Mkdir(ppd.DownloadFolder, os.ModePerm); err != nil {
					return err
				}
			}
		} else {
			if err := os.Mkdir(ppd.DownloadFolder, os.ModePerm); err != nil {
				return err
			}
		}
	} else {
		if stat, err := os.Stat(ppd.OutputFileOrFolder); err == nil {
			if !stat.IsDir() {
				return fmt.Errorf("output path %q exists and is not a directory", ppd.OutputFileOrFolder)
			}
			containsFiles := false
			if files, err := os.ReadDir(ppd.OutputFileOrFolder); err == nil {
				containsFiles = len(files) > 0
			}
			if !ppd.Resume && !ppd.Overwrite && containsFiles {
				return fmt.Errorf("output folder %q already exists and is not empty. Use -o if you want to overwrite it", ppd.OutputFileOrFolder)
			}
			if ppd.Resume && containsFiles {
				fmt.Printf("resuming download of %q\n", ppd.OutputFileOrFolder)
			}
		} else if !os.IsNotExist(err) {
			return err
		} else {
			if err := os.Mkdir(ppd.OutputFileOrFolder, os.ModePerm); err != nil {
				return err
			}
		}
		ppd.DownloadFolder = ppd.OutputFileOrFolder
	}

	maxValue := 1024 * 1024
	bar := progressbar.Default(int64(maxValue))

	g, ctx := errgroup.WithContext(context.Background())
	g.SetLimit(ppd.Parallelism)
	for hashPrefix := range maxValue {
		p := hashPrefix
		g.Go(func() error {
			return ppd.downloadHashes(ctx, bar, p)
		})
	}
	if err := g.Wait(); err != nil {
		return err
	}

	if ppd.SingleFile {
		if err := ppd.mergeFiles(); err != nil {
			return err
		}

		if err := os.RemoveAll(ppd.DownloadFolder); err != nil {
			return err
		}
	}

	_ = bar.Finish()

	fmt.Printf("Cloudflare requests:             %d\n", ppd.Statistics.CloudflareRequests)
	fmt.Printf("Cloudflare hits:                 %d\n", ppd.Statistics.CloudflareHits)
	fmt.Printf("Cloudflare misses:               %d\n", ppd.Statistics.CloudflareMisses)
	if ppd.Statistics.CloudflareRequests > 0 {
		fmt.Printf("Cloudflare hit rate:             %d %%\n", ppd.Statistics.CloudflareHits*100/ppd.Statistics.CloudflareRequests)
	}
	fmt.Printf("Cloudflare request time total:   %d ms\n", ppd.Statistics.CloudflareRequestTimeTotal)
	if ppd.Statistics.CloudflareRequests > 0 {
		fmt.Printf("Cloudflare request time average: %d ms\n", ppd.Statistics.CloudflareRequestTimeTotal/ppd.Statistics.CloudflareRequests)
	}

	return nil
}

func (ppd *PwnedPasswordsDownloader) mergeFiles() error {
	files, err := os.ReadDir(ppd.DownloadFolder)
	if err != nil {
		return err
	}

	outputFile, err := os.Create(ppd.OutputFileOrFolder)
	if err != nil {
		return err
	}

	for _, entry := range files {
		fileName := entry.Name()
		err := func() error {
			f, err := os.Open(filepath.Join(ppd.DownloadFolder, fileName))
			if err != nil {
				return err
			}
			defer f.Close()

			if _, err := io.Copy(outputFile, f); err != nil {
				return err
			}

			return nil
		}()
		if err != nil {
			outputFile.Close()
			return err
		}

		if err := os.Remove(filepath.Join(ppd.DownloadFolder, fileName)); err != nil {
			outputFile.Close()
			return err
		}
	}

	return outputFile.Close()
}

func (ppd *PwnedPasswordsDownloader) downloadHashes(ctx context.Context, bar *progressbar.ProgressBar, prefix int) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	hexPrefix := intToHex(prefix)
	downloadFile := filepath.Join(ppd.DownloadFolder, hexPrefix+".txt")
	if ppd.Resume {
		stat, err := os.Stat(downloadFile)
		if err == nil && stat.Size() > 0 {
			_ = bar.Add(1)
			return nil
		}
	}

	url := hibpURL + hexPrefix
	if ppd.FetchNtlm {
		url += "?mode=ntlm"
	}
	var resp *http.Response
	start := time.Now()
	err := retry.Do(
		func() error {
			if err := ctx.Err(); err != nil {
				return retry.Unrecoverable(err)
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				return retry.Unrecoverable(err)
			}

			req.Header.Set("User-Agent", "hibp-downloader")
			req.Header.Set("Accept-Encoding", "br")

			resp, err = ppd.Client.Do(req)
			if err != nil {
				return err
			}
			if resp.StatusCode != http.StatusOK {
				resp.Body.Close()
				statusErr := &httpStatusError{statusCode: resp.StatusCode}
				if statusErr.Retryable() {
					return statusErr
				}
				return retry.Unrecoverable(statusErr)
			}

			return nil
		},
		retry.Attempts(10),
		retry.RetryIf(func(err error) bool {
			if statusErr, ok := errors.AsType[*httpStatusError](err); ok {
				return statusErr.Retryable()
			}

			return true
		}),
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

	tmpFile := downloadFile + ".tmp"
	f, err := os.Create(tmpFile)
	if err != nil {
		return err
	}

	w := bufio.NewWriterSize(f, 32*1024)
	if _, err := io.Copy(w, reader); err != nil {
		f.Close()
		os.Remove(tmpFile)
		return err
	}
	if err := w.Flush(); err != nil {
		f.Close()
		os.Remove(tmpFile)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmpFile)
		return err
	}

	if err := os.Rename(tmpFile, downloadFile); err != nil {
		os.Remove(tmpFile)
		return err
	}

	_ = bar.Add(1)
	return nil
}

func intToHex(i int) string {
	return strings.ToUpper(fmt.Sprintf("%05x", i))
}
