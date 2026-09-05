package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
)

func TestIntToHex(t *testing.T) {
	tests := map[int]string{
		0:                   "00000",
		1:                   "00001",
		0xabcde:             "ABCDE",
		maxHashPrefixes - 1: "FFFFF",
	}

	for input, want := range tests {
		if got := intToHex(input); got != want {
			t.Fatalf("intToHex(%d) = %q, want %q", input, got, want)
		}
	}
}

func TestHTTPStatusErrorRetryable(t *testing.T) {
	tests := map[int]bool{
		200: false,
		400: false,
		429: true,
		500: true,
		503: true,
	}

	for statusCode, want := range tests {
		err := &httpStatusError{statusCode: statusCode}
		if got := err.Retryable(); got != want {
			t.Fatalf("Retryable(%d) = %t, want %t", statusCode, got, want)
		}
	}
}

func TestReplaceFileRequiresOverwriteForExistingTarget(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source.txt")
	target := filepath.Join(dir, "target.txt")

	if err := os.WriteFile(source, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := replaceFile(source, target, false); err == nil {
		t.Fatal("replaceFile succeeded without overwrite")
	}
}

func TestReplaceFileOverwritesExistingTarget(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source.txt")
	target := filepath.Join(dir, "target.txt")

	if err := os.WriteFile(source, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := replaceFile(source, target, true); err != nil {
		t.Fatal(err)
	}

	contents, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "new" {
		t.Fatalf("target contents = %q, want %q", contents, "new")
	}
}

func TestCopyRangeWithPrefix(t *testing.T) {
	var output bytes.Buffer
	writer := bufio.NewWriter(&output)
	input := strings.NewReader("AAA:1\r\nBBB:2\n")

	if err := copyRangeWithPrefix(writer, input, "12345"); err != nil {
		t.Fatal(err)
	}
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}

	want := "12345AAA:1\r\n12345BBB:2\r\n"
	if got := output.String(); got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
}

func TestMergeFilesCreatesCompleteHashesInPrefixOrder(t *testing.T) {
	dir := t.TempDir()
	downloadDir := filepath.Join(dir, "ranges")
	if err := os.Mkdir(downloadDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(downloadDir, "00001.txt"), "BBB:2\r\n")
	writeTestFile(t, filepath.Join(downloadDir, "00000.txt"), "AAA:1\r\n")

	output := filepath.Join(dir, "passwords.txt")
	ppd := PwnedPasswordsDownloader{
		DownloadFolder:     downloadDir,
		OutputFileOrFolder: output,
	}
	if err := ppd.mergeFiles(context.Background(), 2); err != nil {
		t.Fatal(err)
	}

	contents, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	want := "00000AAA:1\r\n00001BBB:2\r\n"
	if got := string(contents); got != want {
		t.Fatalf("merged output = %q, want %q", got, want)
	}
}

func TestMergeFilesKeepsExistingOutputOnFailure(t *testing.T) {
	dir := t.TempDir()
	downloadDir := filepath.Join(dir, "ranges")
	if err := os.Mkdir(downloadDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(downloadDir, "00000.txt"), "AAA:1\r\n")
	output := filepath.Join(dir, "passwords.txt")
	writeTestFile(t, output, "existing")

	ppd := PwnedPasswordsDownloader{
		DownloadFolder:     downloadDir,
		OutputFileOrFolder: output,
		Overwrite:          true,
	}
	if err := ppd.mergeFiles(context.Background(), 2); err == nil {
		t.Fatal("mergeFiles succeeded with a missing range")
	}

	contents, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(contents); got != "existing" {
		t.Fatalf("existing output changed to %q", got)
	}
}

func TestPrepareOutputRejectsDirectoryForSingleFile(t *testing.T) {
	ppd := PwnedPasswordsDownloader{
		OutputFileOrFolder: t.TempDir(),
		SingleFile:         true,
		Overwrite:          true,
	}

	if err := ppd.prepareOutput(); err == nil {
		t.Fatal("prepareOutput accepted a directory as a single-file output")
	}
}

func TestDownloadHashesResumeReplacesEmptyRange(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if got := r.Header.Get("User-Agent"); !strings.HasPrefix(got, "hibp-passwords-downloader/") {
			t.Errorf("User-Agent = %q", got)
		}
		_, _ = fmt.Fprint(w, "ABC:1\r\n")
	}))
	defer server.Close()

	dir := t.TempDir()
	target := filepath.Join(dir, "00000.txt")
	writeTestFile(t, target, "")
	ppd := PwnedPasswordsDownloader{
		Client:         server.Client(),
		DownloadFolder: dir,
		Resume:         true,
		baseURL:        server.URL + "/",
	}

	if err := ppd.downloadHashes(context.Background(), nil, 0); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(contents); got != "ABC:1\r\n" {
		t.Fatalf("range contents = %q", got)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("requests = %d, want 1", got)
	}
}

func TestDownloadHashesResumeSkipsNonemptyRange(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = fmt.Fprint(w, "replacement")
	}))
	defer server.Close()

	dir := t.TempDir()
	target := filepath.Join(dir, "00000.txt")
	writeTestFile(t, target, "existing")
	ppd := PwnedPasswordsDownloader{
		Client:         server.Client(),
		DownloadFolder: dir,
		Resume:         true,
		baseURL:        server.URL + "/",
	}

	if err := ppd.downloadHashes(context.Background(), nil, 0); err != nil {
		t.Fatal(err)
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("requests = %d, want 0", got)
	}
}

func TestDownloadHashesRejectsEmptyResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()

	dir := t.TempDir()
	ppd := PwnedPasswordsDownloader{
		Client:         server.Client(),
		DownloadFolder: dir,
		baseURL:        server.URL + "/",
	}
	err := ppd.downloadHashes(context.Background(), nil, 0)
	if err == nil || !strings.Contains(err.Error(), "empty response") {
		t.Fatalf("error = %v, want empty response error", err)
	}
	for _, name := range []string{"00000.txt", "00000.txt.tmp"} {
		if _, err := os.Stat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s was not cleaned up", name)
		}
	}
}

func TestDownloadHashesDecodesBrotli(t *testing.T) {
	var compressed bytes.Buffer
	brotliWriter := brotli.NewWriter(&compressed)
	if _, err := brotliWriter.Write([]byte("ABC:1\r\n")); err != nil {
		t.Fatal(err)
	}
	if err := brotliWriter.Close(); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Encoding", "br")
		_, _ = w.Write(compressed.Bytes())
	}))
	defer server.Close()

	dir := t.TempDir()
	ppd := PwnedPasswordsDownloader{
		Client:         server.Client(),
		DownloadFolder: dir,
		baseURL:        server.URL + "/",
	}
	if err := ppd.downloadHashes(context.Background(), nil, 0); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(filepath.Join(dir, "00000.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if got := string(contents); got != "ABC:1\r\n" {
		t.Fatalf("decoded contents = %q", got)
	}
}

func TestGetWithRetriesTracksEveryAttempt(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if requests.Add(1) == 1 {
			w.Header().Set("Cf-Cache-Status", "MISS")
			http.Error(w, "try again", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Cf-Cache-Status", "HIT")
		_, _ = fmt.Fprint(w, "ok")
	}))
	defer server.Close()

	var ppd PwnedPasswordsDownloader
	ppd.Client = server.Client()
	resp, err := ppd.getWithRetries(context.Background(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if got := atomic.LoadUint64(&ppd.Statistics.CloudflareRequests); got != 2 {
		t.Fatalf("tracked requests = %d, want 2", got)
	}
	if got := atomic.LoadUint64(&ppd.Statistics.CloudflareHits); got != 1 {
		t.Fatalf("tracked hits = %d, want 1", got)
	}
	if got := atomic.LoadUint64(&ppd.Statistics.CloudflareMisses); got != 1 {
		t.Fatalf("tracked misses = %d, want 1", got)
	}
}

func TestGetWithRetriesCanCancelRetryAfterDelay(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusServiceUnavailable)
		cancel()
	}))
	defer server.Close()

	ppd := PwnedPasswordsDownloader{Client: server.Client()}
	_, err := ppd.getWithRetries(ctx, server.URL)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context cancellation", err)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("requests = %d, want 1", got)
	}
}

func TestDownloadAllStopsSchedulingAfterFailure(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		http.Error(w, "bad request", http.StatusBadRequest)
	}))
	defer server.Close()

	ppd := PwnedPasswordsDownloader{
		Client:         server.Client(),
		DownloadFolder: t.TempDir(),
		Parallelism:    4,
		baseURL:        server.URL + "/",
	}
	if err := ppd.downloadAll(context.Background(), nil, 1000); err == nil {
		t.Fatal("downloadAll succeeded")
	}
	if got := requests.Load(); got >= 20 {
		t.Fatalf("downloadAll made %d requests after an immediate failure", got)
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, time.September, 5, 10, 0, 0, 0, time.UTC)
	tests := map[string]time.Duration{
		"":        0,
		"5":       5 * time.Second,
		"invalid": 0,
		now.Add(12 * time.Second).Format(http.TimeFormat): 12 * time.Second,
		"3600": maxRetryDelay,
	}
	for input, want := range tests {
		if got := parseRetryAfter(input, now); got != want {
			t.Errorf("parseRetryAfter(%q) = %v, want %v", input, got, want)
		}
	}
}

func writeTestFile(t *testing.T, name, contents string) {
	t.Helper()
	if err := os.WriteFile(name, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}
