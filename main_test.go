package main

import (
	"os"
	"path/filepath"
	"testing"
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
