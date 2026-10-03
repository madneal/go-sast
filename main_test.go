package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanTextContentFindsHardcodedValuesAndIgnoresPlaceholders(t *testing.T) {
	findings := scanTextContent("config.yaml", "password: super-secret-value\nsourcegraph-token: ${TOKEN}\n")
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %#v", len(findings), findings)
	}
	if findings[0].Evidence != "password = su****ue" {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}
}

func TestScanGoFindsHardcodedValues(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "main.go")
	if err := os.WriteFile(path, []byte("package main\n\nconst apiKey = \"abcd1234\"\nvar token = os.Getenv(\"TOKEN\")\n"), 0600); err != nil {
		t.Fatal(err)
	}
	findings, err := scanGo(path, "main.go")
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Evidence != "apiKey = ab****34" {
		t.Fatalf("unexpected findings: %#v", findings)
	}
}
