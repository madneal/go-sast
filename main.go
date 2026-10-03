package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"log"
	"net/http"
	"os"
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

type File struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

type ScanRequest struct {
	Files []File `json:"files"`
}

type ScanResponse struct {
	Findings []Finding `json:"findings"`
	Count    int       `json:"count"`
}

var (
	secretName  = regexp.MustCompile(`(?i)(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|signing[_-]?key|client[_-]?secret|authorization)`)
	assignment  = regexp.MustCompile(`(?i)["']?(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|signing[_-]?key|client[_-]?secret|authorization)["']?\s*[:=]\s*["']?([^"'\s},]+)`)
	placeholder = regexp.MustCompile(`(?i)^(changeme|change[_-]?me|example|sample|placeholder|redacted|xxx+|none|null|nil|your[_-].*|<.*>|\$\{.*\})$`)
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthHandler)
	mux.HandleFunc("/scan", scanHandler)
	mux.HandleFunc("/", infoHandler)

	log.Printf("go-sast listening on :%s", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatal(err)
	}
}

func infoHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"service":  "go-sast",
		"endpoint": "POST /scan",
	})
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func scanHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST /scan is required"})
		return
	}

	var request ScanRequest
	decoder := json.NewDecoder(io.LimitReader(r.Body, 16<<20))
	if err := decoder.Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
		return
	}
	if len(request.Files) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "files must not be empty"})
		return
	}

	response := ScanResponse{Findings: scanFiles(request.Files)}
	response.Count = len(response.Findings)
	writeJSON(w, http.StatusOK, response)
}

func scanFiles(files []File) []Finding {
	findings := make([]Finding, 0)
	seen := make(map[string]bool)
	for _, file := range files {
		var current []Finding
		if strings.EqualFold(extension(file.Path), ".go") {
			current = scanGo(file.Path, file.Content)
		} else if isTextFile(file.Path) {
			current = scanText(file.Path, file.Content)
		}
		for _, finding := range current {
			key := fmt.Sprintf("%s:%d:%s", finding.Path, finding.Line, finding.Evidence)
			if !seen[key] {
				seen[key] = true
				findings = append(findings, finding)
			}
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Path == findings[j].Path {
			return findings[i].Line < findings[j].Line
		}
		return findings[i].Path < findings[j].Path
	})
	return findings
}

func scanGo(path, source string) []Finding {
	fileSet := token.NewFileSet()
	file, err := parser.ParseFile(fileSet, path, source, 0)
	if err != nil {
		return nil
	}

	findings := make([]Finding, 0)
	ast.Inspect(file, func(node ast.Node) bool {
		var name string
		var value ast.Expr
		switch item := node.(type) {
		case *ast.ValueSpec:
			for i, identifier := range item.Names {
				if i < len(item.Values) && secretName.MatchString(identifier.Name) {
					addGoFinding(&findings, fileSet, path, identifier.Name, item.Values[i])
				}
			}
		case *ast.AssignStmt:
			for i, left := range item.Lhs {
				identifier, ok := left.(*ast.Ident)
				if ok && i < len(item.Rhs) && secretName.MatchString(identifier.Name) {
					addGoFinding(&findings, fileSet, path, identifier.Name, item.Rhs[i])
				}
			}
		case *ast.KeyValueExpr:
			name = expressionName(item.Key)
			value = item.Value
		}
		if name != "" && secretName.MatchString(name) {
			addGoFinding(&findings, fileSet, path, name, value)
		}
		return true
	})
	return findings
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

func scanText(path, source string) []Finding {
	findings := make([]Finding, 0)
	for lineNumber, line := range strings.Split(source, "\n") {
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

func extension(path string) string {
	index := strings.LastIndex(path, ".")
	if index < 0 {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(path[index:]))
}

func isTextFile(path string) bool {
	switch extension(path) {
	case ".conf", ".env", ".ini", ".js", ".json", ".jsx", ".properties", ".py", ".rs", ".toml", ".ts", ".tsx", ".vue", ".yaml", ".yml":
		return true
	default:
		return strings.HasSuffix(strings.ToLower(path), ".env")
	}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
