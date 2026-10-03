package main

import "testing"

func TestScanFilesFindsHardcodedValuesAndIgnoresPlaceholders(t *testing.T) {
	findings := scanFiles([]File{
		{Path: "config.yaml", Content: "password: super-secret-value\nsourcegraph-token: ${TOKEN}\n"},
		{Path: "main.go", Content: "package main\n\nconst apiKey = \"abcd1234\"\nvar token = os.Getenv(\"TOKEN\")\n"},
	})

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d: %#v", len(findings), findings)
	}
	if findings[0].Evidence != "password = su****ue" {
		t.Fatalf("unexpected first finding: %#v", findings[0])
	}
	if findings[1].Evidence != "apiKey = ab****34" {
		t.Fatalf("unexpected second finding: %#v", findings[1])
	}
}
