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
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
)

const (
	hibpURL         = "https://api.pwnedpasswords.com/range/"
	maxHashPrefixes = 1024 * 1024
	requestAttempts = 10
	maxParallelism  = 64
	maxRetryDelay   = time.Minute
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
	baseURL            string
}

var version = "dev"

type httpStatusError struct {
	statusCode int
	retryAfter time.Duration
}

func (e *httpStatusError) Error() string {
	return fmt.Sprintf("unexpected HTTP status: %d", e.statusCode)
}

func (e *httpStatusError) Retryable() bool {
	return e.statusCode == http.StatusTooManyRequests || e.statusCode >= http.StatusInternalServerError
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var ppd PwnedPasswordsDownloader
	cmd := &cobra.Command{
		Use:     "hibp-passwords-downloader [outputFileOrFolder]",
		Short:   "Downloads Have I Been Pwned passwords hashes lists to find compromised passwords",
		Args:    cobra.MaximumNArgs(1),
		Version: version,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				ppd.OutputFileOrFolder = args[0]
			} else if ppd.SingleFile {
				ppd.OutputFileOrFolder = "hibp-passwords.txt"
			} else {
				ppd.OutputFileOrFolder = "hibp-passwords"
			}
			if ppd.Parallelism < 0 {
				return fmt.Errorf("parallelism must be greater than or equal to 0")
			}
			if ppd.Parallelism == 0 {
				ppd.Parallelism = min(runtime.NumCPU()*8, maxParallelism)
			} else {
				ppd.Parallelism = min(ppd.Parallelism, maxParallelism)
			}

			transport := http.DefaultTransport.(*http.Transport).Clone()
			transport.MaxIdleConnsPerHost = ppd.Parallelism
			ppd.Client = &http.Client{Timeout: 60 * time.Second, Transport: transport}
			cmd.SilenceUsage = true
			return ppd.execute(cmd.Context())
		},
	}

	cmd.Flags().IntVarP(&ppd.Parallelism, "parallelism", "p", 0, "The number of parallel requests to make to Have I Been Pwned to download the hash ranges. If omitted, defaults to eight times the number of processors on the machine. Maximum 64; values above 64 are capped")
	cmd.Flags().BoolVarP(&ppd.Overwrite, "overwrite", "o", false, "When set, overwrite any existing files while writing the results. Defaults to false.")
	cmd.Flags().BoolVarP(&ppd.SingleFile, "single", "s", false, "When set, writes the hash ranges into a single .txt file. Otherwise downloads ranges to individual files into a subfolder. If omitted defaults to individual files.")
	cmd.Flags().BoolVarP(&ppd.FetchNtlm, "ntlm", "n", false, "When set, fetches NTLM hashes instead of SHA1.")
	cmd.Flags().BoolVarP(&ppd.Resume, "resume", "r", false, "When set, resumes download of existing files.")

	if err := cmd.ExecuteContext(ctx); err != nil {
		os.Exit(1)
	}
}

func (ppd *PwnedPasswordsDownloader) execute(ctx context.Context) error {
	if ppd.Parallelism < 1 {
		return fmt.Errorf("parallelism must be greater than 0")
	}
	if ppd.Client == nil {
		return fmt.Errorf("HTTP client is not configured")
	}
	if err := ppd.prepareOutput(); err != nil {
		return err
	}

	bar := progressbar.Default(int64(maxHashPrefixes))
	if err := ppd.downloadAll(ctx, bar, maxHashPrefixes); err != nil {
		_ = bar.Exit()
		return err
	}
	_ = bar.Finish()

	if ppd.SingleFile {
		if err := ppd.mergeFiles(ctx, maxHashPrefixes); err != nil {
			return err
		}

		if err := os.RemoveAll(ppd.DownloadFolder); err != nil {
			return err
		}
	}

	ppd.printStatistics()
	return nil
}

func (ppd *PwnedPasswordsDownloader) prepareOutput() error {
	if ppd.SingleFile {
		if stat, err := os.Stat(ppd.OutputFileOrFolder); err == nil {
			if stat.IsDir() {
				return fmt.Errorf("output path %q is a directory", ppd.OutputFileOrFolder)
			}
			if !ppd.Overwrite {
				return fmt.Errorf("output file %q already exists. Use -o if you want to overwrite it", ppd.OutputFileOrFolder)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		ppd.DownloadFolder = filepath.Join(filepath.Dir(ppd.OutputFileOrFolder), ".hibp_"+filepath.Base(ppd.OutputFileOrFolder))

		if stat, err := os.Stat(ppd.DownloadFolder); err == nil {
			if ppd.Resume {
				if !stat.IsDir() {
					return fmt.Errorf("resume path %q is not a directory", ppd.DownloadFolder)
				}
				fmt.Printf("resuming download of %q\n", ppd.OutputFileOrFolder)
			} else {
				if err := os.RemoveAll(ppd.DownloadFolder); err != nil {
					return err
				}
				if err := os.MkdirAll(ppd.DownloadFolder, 0o755); err != nil {
					return err
				}
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		} else {
			if err := os.MkdirAll(ppd.DownloadFolder, 0o755); err != nil {
				return err
			}
		}
	} else {
		if stat, err := os.Stat(ppd.OutputFileOrFolder); err == nil {
			if !stat.IsDir() {
				return fmt.Errorf("output path %q exists and is not a directory", ppd.OutputFileOrFolder)
			}
			files, err := os.ReadDir(ppd.OutputFileOrFolder)
			if err != nil {
				return err
			}
			containsFiles := len(files) > 0
			if !ppd.Resume && !ppd.Overwrite && containsFiles {
				return fmt.Errorf("output folder %q already exists and is not empty. Use -o if you want to overwrite it", ppd.OutputFileOrFolder)
			}
			if ppd.Resume && containsFiles {
				fmt.Printf("resuming download of %q\n", ppd.OutputFileOrFolder)
			}
		} else if !os.IsNotExist(err) {
			return err
		} else {
			if err := os.MkdirAll(ppd.OutputFileOrFolder, 0o755); err != nil {
				return err
			}
		}
		ppd.DownloadFolder = ppd.OutputFileOrFolder
	}

	return nil
}

func (ppd *PwnedPasswordsDownloader) downloadAll(ctx context.Context, bar *progressbar.ProgressBar, prefixCount int) error {
	g, ctx := errgroup.WithContext(ctx)
	var nextPrefix atomic.Int64
	for range min(ppd.Parallelism, prefixCount) {
		g.Go(func() error {
			for {
				if err := ctx.Err(); err != nil {
					return err
				}
				prefix := int(nextPrefix.Add(1) - 1)
				if prefix >= prefixCount {
					return nil
				}
				if err := ppd.downloadHashes(ctx, bar, prefix); err != nil {
					return fmt.Errorf("download range %s: %w", intToHex(prefix), err)
				}
			}
		})
	}
	return g.Wait()
}

func (ppd *PwnedPasswordsDownloader) printStatistics() {
	cfRequests := atomic.LoadUint64(&ppd.Statistics.CloudflareRequests)
	cfHits := atomic.LoadUint64(&ppd.Statistics.CloudflareHits)
	cfMisses := atomic.LoadUint64(&ppd.Statistics.CloudflareMisses)
	cfRequestTime := atomic.LoadUint64(&ppd.Statistics.CloudflareRequestTimeTotal)

	fmt.Printf("Cloudflare requests:             %d\n", cfRequests)
	fmt.Printf("Cloudflare hits:                 %d\n", cfHits)
	fmt.Printf("Cloudflare misses:               %d\n", cfMisses)
	cacheResponses := cfHits + cfMisses
	if cacheResponses > 0 {
		fmt.Printf("Cloudflare hit rate:             %d %%\n", cfHits*100/cacheResponses)
	}
	fmt.Printf("Cloudflare request time total:   %d ms\n", cfRequestTime)
	if cfRequests > 0 {
		fmt.Printf("Cloudflare request time average: %d ms\n", cfRequestTime/cfRequests)
	}
}

func (ppd *PwnedPasswordsDownloader) mergeFiles(ctx context.Context, prefixCount int) (retErr error) {
	mergedFile := filepath.Join(ppd.DownloadFolder, ".merged.tmp")
	outputFile, err := os.Create(mergedFile)
	if err != nil {
		return err
	}
	closed := false
	preserveMergedFile := false
	defer func() {
		if !closed {
			if err := outputFile.Close(); err != nil && retErr == nil {
				retErr = err
			}
		}
		if !preserveMergedFile {
			_ = os.Remove(mergedFile)
		}
	}()

	writer := bufio.NewWriterSize(outputFile, 1024*1024)
	for prefix := range prefixCount {
		if err := ctx.Err(); err != nil {
			return err
		}

		hexPrefix := intToHex(prefix)
		fileName := filepath.Join(ppd.DownloadFolder, hexPrefix+".txt")
		f, err := os.Open(fileName)
		if err != nil {
			return fmt.Errorf("open range %s: %w", hexPrefix, err)
		}
		copyErr := copyRangeWithPrefix(writer, f, hexPrefix)
		closeErr := f.Close()
		if copyErr != nil {
			return fmt.Errorf("merge range %s: %w", hexPrefix, copyErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close range %s: %w", hexPrefix, closeErr)
		}
		if err := os.Remove(fileName); err != nil {
			return fmt.Errorf("remove merged range %s: %w", hexPrefix, err)
		}
	}

	if err := writer.Flush(); err != nil {
		return err
	}
	if err := outputFile.Close(); err != nil {
		closed = true
		return err
	}
	closed = true
	preserveMergedFile = true
	if err := replaceFile(mergedFile, ppd.OutputFileOrFolder, ppd.Overwrite); err != nil {
		return fmt.Errorf("install merged output (complete file preserved at %q): %w", mergedFile, err)
	}
	preserveMergedFile = false
	return nil
}

func copyRangeWithPrefix(dst *bufio.Writer, src io.Reader, prefix string) error {
	scanner := bufio.NewScanner(src)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		if _, err := dst.WriteString(prefix); err != nil {
			return err
		}
		if _, err := dst.Write(line); err != nil {
			return err
		}
		if _, err := dst.WriteString("\r\n"); err != nil {
			return err
		}
	}
	return scanner.Err()
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
			advanceProgress(bar)
			return nil
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}

	baseURL := ppd.baseURL
	if baseURL == "" {
		baseURL = hibpURL
	}
	url := baseURL + hexPrefix
	if ppd.FetchNtlm {
		url += "?mode=ntlm"
	}
	resp, err := ppd.getWithRetries(ctx, url)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	var reader io.Reader = resp.Body
	contentEncoding := strings.TrimSpace(resp.Header.Get("Content-Encoding"))
	switch {
	case contentEncoding == "", strings.EqualFold(contentEncoding, "identity"):
	case strings.EqualFold(contentEncoding, "br"):
		reader = brotli.NewReader(resp.Body)
	default:
		return fmt.Errorf("unsupported content encoding %q", contentEncoding)
	}

	tmpFile := downloadFile + ".tmp"
	f, err := os.Create(tmpFile)
	if err != nil {
		return err
	}

	written, err := io.Copy(f, reader)
	if err != nil {
		_ = f.Close()
		_ = os.Remove(tmpFile)
		return err
	}
	if written == 0 {
		_ = f.Close()
		_ = os.Remove(tmpFile)
		return fmt.Errorf("empty response")
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpFile)
		return err
	}

	if err := replaceFile(tmpFile, downloadFile, ppd.Overwrite || ppd.Resume); err != nil {
		_ = os.Remove(tmpFile)
		return err
	}

	advanceProgress(bar)
	return nil
}

func advanceProgress(bar *progressbar.ProgressBar) {
	if bar != nil {
		_ = bar.Add(1)
	}
}

func (ppd *PwnedPasswordsDownloader) getWithRetries(ctx context.Context, url string) (*http.Response, error) {
	var lastErr error

	for attempt := 1; attempt <= requestAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "hibp-passwords-downloader/"+version)
		req.Header.Set("Accept-Encoding", "br")

		start := time.Now()
		resp, err := ppd.Client.Do(req)
		requestDuration := time.Since(start)
		atomic.AddUint64(&ppd.Statistics.CloudflareRequests, 1)
		atomic.AddUint64(&ppd.Statistics.CloudflareRequestTimeTotal, uint64(requestDuration.Milliseconds()))
		if resp != nil {
			switch {
			case strings.EqualFold(resp.Header.Get("Cf-Cache-Status"), "HIT"):
				atomic.AddUint64(&ppd.Statistics.CloudflareHits, 1)
			case strings.EqualFold(resp.Header.Get("Cf-Cache-Status"), "MISS"):
				atomic.AddUint64(&ppd.Statistics.CloudflareMisses, 1)
			}
		}
		if err == nil && resp.StatusCode == http.StatusOK {
			return resp, nil
		}

		if err != nil {
			if resp != nil {
				_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))
				_ = resp.Body.Close()
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			lastErr = err
		} else {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))
			_ = resp.Body.Close()
			statusErr := &httpStatusError{
				statusCode: resp.StatusCode,
				retryAfter: parseRetryAfter(resp.Header.Get("Retry-After"), time.Now()),
			}
			if !statusErr.Retryable() {
				return nil, statusErr
			}
			lastErr = statusErr
		}

		if attempt < requestAttempts {
			log.Printf("Retrying request after error: %v", lastErr)
			if err := sleepWithContext(ctx, retryDelay(attempt, lastErr)); err != nil {
				return nil, err
			}
		}
	}

	return nil, lastErr
}

func retryDelay(attempt int, err error) time.Duration {
	delay := min(time.Duration(attempt)*250*time.Millisecond, 2*time.Second)
	var statusErr *httpStatusError
	if errors.As(err, &statusErr) && statusErr.retryAfter > delay {
		return statusErr.retryAfter
	}
	return delay
}

func parseRetryAfter(value string, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		if seconds <= 0 {
			return 0
		}
		if seconds >= int64(maxRetryDelay/time.Second) {
			return maxRetryDelay
		}
		return time.Duration(seconds) * time.Second
	}
	if retryAt, err := http.ParseTime(value); err == nil {
		return min(max(retryAt.Sub(now), 0), maxRetryDelay)
	}
	return 0
}

func sleepWithContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func replaceFile(source, target string, overwrite bool) error {
	if !overwrite {
		if _, err := os.Stat(target); err == nil {
			return fmt.Errorf("target file %q already exists", target)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return os.Rename(source, target)
	}

	if err := os.Remove(target); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Rename(source, target)
}

func intToHex(i int) string {
	return fmt.Sprintf("%05X", i)
}
