package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type Finding struct {
	Path     string `json:"path"`
	Line     int    `json:"line"`
	Kind     string `json:"kind"`
	Evidence string `json:"evidence"`
}

var (
	secretName  = regexp.MustCompile(`(?i)(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|signing[_-]?key|client[_-]?secret|authorization)`)
	assignment  = regexp.MustCompile(`(?i)["']?(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|signing[_-]?key|client[_-]?secret|authorization)["']?\s*[:=]\s*["']?([^"'\s},]+)`)
	placeholder = regexp.MustCompile(`(?i)^(changeme|change[_-]?me|example|sample|placeholder|redacted|xxx+|none|null|nil|read|write|your[_-].*|<.*>|\$\{.*\})$`)
)

var textExtensions = map[string]bool{
	".conf": true, ".env": true, ".ini": true, ".js": true, ".json": true,
	".jsx": true, ".properties": true, ".py": true, ".rs": true, ".toml": true,
	".ts": true, ".tsx": true, ".vue": true, ".yaml": true, ".yml": true,
}

func main() {
	root := flag.String("path", ".", "file or directory to scan")
	format := flag.String("format", "text", "output format: text or json")
	failOnFindings := flag.Bool("fail-on-findings", false, "exit 1 when findings are found")
	flag.Parse()
	if flag.NArg() > 0 {
		*root = flag.Arg(0)
	}

	findings, err := scan(*root)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Path == findings[j].Path {
			return findings[i].Line < findings[j].Line
		}
		return findings[i].Path < findings[j].Path
	})

	switch *format {
	case "json":
		output, err := json.MarshalIndent(struct {
			Findings []Finding `json:"findings"`
			Count    int       `json:"count"`
		}{findings, len(findings)}, "", "  ")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		fmt.Println(string(output))
	case "text":
		for _, finding := range findings {
			fmt.Printf("%s:%d: %s: %s\n", finding.Path, finding.Line, finding.Kind, finding.Evidence)
		}
		fmt.Printf("Findings: %d\n", len(findings))
	default:
		fmt.Fprintf(os.Stderr, "unsupported format %q\n", *format)
		os.Exit(2)
	}

	if *failOnFindings && len(findings) > 0 {
		os.Exit(1)
	}
}

func scan(root string) ([]Finding, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}

	base := root
	if !info.IsDir() {
		base = filepath.Dir(root)
	}
	findings := make([]Finding, 0)
	err = filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() {
			if path != root && skipDir(info.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if info.Size() > 2<<20 || skipFile(path) {
			return nil
		}

		relPath, err := filepath.Rel(base, path)
		if err != nil {
			return err
		}
		if filepath.Ext(path) == ".go" {
			fileFindings, err := scanGo(path, relPath)
			if err != nil {
				return err
			}
			findings = append(findings, fileFindings...)
		} else if textExtensions[filepath.Ext(path)] || filepath.Base(path) == ".env" {
			fileFindings, err := scanText(path, relPath)
			if err != nil {
				return err
			}
			findings = append(findings, fileFindings...)
		}
		return nil
	})
	return findings, err
}

func scanGo(path, displayPath string) ([]Finding, error) {
	fileSet := token.NewFileSet()
	file, err := parser.ParseFile(fileSet, path, nil, 0)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	findings := make([]Finding, 0)
	ast.Inspect(file, func(node ast.Node) bool {
		var name string
		var value ast.Expr
		switch item := node.(type) {
		case *ast.ValueSpec:
			for i, identifier := range item.Names {
				if i < len(item.Values) && secretName.MatchString(identifier.Name) {
					addGoFinding(&findings, fileSet, displayPath, identifier.Name, item.Values[i])
				}
			}
		case *ast.AssignStmt:
			for i, left := range item.Lhs {
				identifier, ok := left.(*ast.Ident)
				if ok && i < len(item.Rhs) && secretName.MatchString(identifier.Name) {
					addGoFinding(&findings, fileSet, displayPath, identifier.Name, item.Rhs[i])
				}
			}
		case *ast.KeyValueExpr:
			name = expressionName(item.Key)
			value = item.Value
		}
		if name != "" && secretName.MatchString(name) {
			addGoFinding(&findings, fileSet, displayPath, name, value)
		}
		return true
	})
	return findings, nil
}

func addGoFinding(findings *[]Finding, fileSet *token.FileSet, path, name string, value ast.Expr) {
	literal, ok := value.(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return
	}
	decoded, err := strconv.Unquote(literal.Value)
	if err != nil || isPlaceholder(decoded) {
		return
	}
	*findings = append(*findings, Finding{
		Path:     path,
		Line:     fileSet.Position(literal.Pos()).Line,
		Kind:     "hardcoded-secret",
		Evidence: fmt.Sprintf("%s = %s", name, mask(decoded)),
	})
}

func scanText(path, displayPath string) ([]Finding, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return scanTextContent(displayPath, string(content)), nil
}

func scanTextContent(path, content string) []Finding {
	findings := make([]Finding, 0)
	for lineNumber, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") {
			continue
		}
		match := assignment.FindStringSubmatch(line)
		if len(match) != 3 || isPlaceholder(match[2]) {
			continue
		}
		findings = append(findings, Finding{
			Path:     path,
			Line:     lineNumber + 1,
			Kind:     "hardcoded-secret",
			Evidence: fmt.Sprintf("%s = %s", match[1], mask(match[2])),
		})
	}
	return findings
}

func expressionName(expression ast.Expr) string {
	switch item := expression.(type) {
	case *ast.Ident:
		return item.Name
	case *ast.BasicLit:
		name, err := strconv.Unquote(item.Value)
		if err == nil {
			return name
		}
	}
	return ""
}

func isPlaceholder(value string) bool {
	value = strings.TrimSpace(value)
	return value == "" || strings.HasPrefix(value, "${") || placeholder.MatchString(value)
}

func mask(value string) string {
	if len(value) <= 4 {
		return "****"
	}
	return value[:2] + "****" + value[len(value)-2:]
}

func skipDir(name string) bool {
	switch name {
	case ".git", ".idea", "node_modules", "dist", "build", "vendor", "release", "coverage":
		return true
	default:
		return false
	}
}

func skipFile(path string) bool {
	name := filepath.Base(path)
	return strings.HasSuffix(name, ".min.js") || strings.HasSuffix(name, ".sum") || strings.HasSuffix(name, ".lock")
}
