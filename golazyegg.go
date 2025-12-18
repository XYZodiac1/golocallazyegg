package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

/* =======================
   Regex definitions
   ======================= */

var (
	tldRegex = regexp.MustCompile(`\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:dev|stg|prod|local|com|net|org|edu|gov|mil|biz|xyz|co|us)\b`)
	ipRegex  = regexp.MustCompile(`\b(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}\b`)

	leakCredsRegex = regexp.MustCompile(
		`(?i)((api_key|password|secret|token|access_key|auth_token)[a-z0-9_ .-]{0,25})(=|:).{0,5}["']([^"']{1,64})["']`,
	)

	cookieRegex      = regexp.MustCompile(`document\.cookie\s*=\s*["']([^"']+)["']`)
	localStoreRegex  = regexp.MustCompile(`localStorage\.setItem\s*\(\s*["']([^"']+)["']\s*,\s*["']([^"']+)["']`)
	oxRegex          = regexp.MustCompile(`\b\w+(?:\.\w+)?\s*\(\s*["']([^"']+)["']`)
	urlRegex         = regexp.MustCompile(`https?://[^\s"'<>]+`)
)

/* =======================
   Options
   ======================= */

type Options struct {
	JSUrls       bool
	Domains      bool
	IPs          bool
	LeakedCreds  bool
	OxCookies    bool
	LocalStorage bool
	OxRegex      bool
	LocalMode    bool
}

/* =======================
   Core logic
   ======================= */

func analyzeJS(content string, opts Options, results map[string][]string) {

	if opts.JSUrls {
		results["js_urls"] = append(results["js_urls"], urlRegex.FindAllString(content, -1)...)
	}
	if opts.Domains {
		results["domains"] = append(results["domains"], tldRegex.FindAllString(content, -1)...)
	}
	if opts.IPs {
		results["ips"] = append(results["ips"], ipRegex.FindAllString(content, -1)...)
	}
	if opts.LeakedCreds {
		matches := leakCredsRegex.FindAllStringSubmatch(content, -1)
		for _, m := range matches {
			results["leaked_creds"] = append(results["leaked_creds"], m[0])
		}
	}
	if opts.OxCookies {
		results["oxcookies"] = append(results["oxcookies"], cookieRegex.FindAllString(content, -1)...)
	}
	if opts.LocalStorage {
		results["local_storage"] = append(results["local_storage"], localStoreRegex.FindAllString(content, -1)...)
	}
	if opts.OxRegex {
		results["oxregex"] = append(results["oxregex"], oxRegex.FindAllString(content, -1)...)
	}
}

/* =======================
   Local JS scanning
   ======================= */

func scanLocalJS(patterns []string, opts Options) {
	results := make(map[string][]string)

	for _, pattern := range patterns {
		files, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}

		for _, file := range files {
			data, err := os.ReadFile(file)
			if err != nil {
				continue
			}
			analyzeJS(string(data), opts, results)
		}
	}

	printResults(results)
}

/* =======================
   Remote JS scanning
   ======================= */

func scanRemoteJS(target string, opts Options) {
	client := &http.Client{Timeout: 10 * time.Second}

	resp, err := client.Get(target)
	if err != nil {
		fmt.Println("Request failed:", err)
		return
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Failed to read response body")
		return
	}

	results := make(map[string][]string)
	analyzeJS(string(bodyBytes), opts, results)
	printResults(results)
}

/* =======================
   Output
   ======================= */

func printResults(results map[string][]string) {
	for key, values := range results {
		fmt.Printf("\n\033[1;33m%s:\033[0m\n", strings.ToUpper(key))

		seen := make(map[string]bool)
		for _, v := range values {
			if !seen[v] {
				fmt.Println(v)
				seen[v] = true
			}
		}
	}
}

/* =======================
   Main
   ======================= */

func main() {

	opts := Options{}

	flag.BoolVar(&opts.JSUrls, "js_urls", false, "Extract JS URLs")
	flag.BoolVar(&opts.Domains, "domains", false, "Extract domains")
	flag.BoolVar(&opts.IPs, "ips", false, "Extract IPs")
	flag.BoolVar(&opts.LeakedCreds, "leaked_creds", false, "Extract leaked credentials")
	flag.BoolVar(&opts.OxCookies, "oxcookies", false, "Extract cookies in JS")
	flag.BoolVar(&opts.LocalStorage, "local_storage", false, "Extract localStorage")
	flag.BoolVar(&opts.OxRegex, "oxregex", false, "Extract OxRegex patterns")
	flag.BoolVar(&opts.LocalMode, "local", false, "Scan local JS files")
	flag.BoolVar(&opts.LocalMode, "l", false, "Scan local JS files (short)")

	flag.Parse()
	args := flag.Args()

	if opts.LocalMode {
		if len(args) == 0 {
			fmt.Println("No JS files provided")
			return
		}
		scanLocalJS(args, opts)
		return
	}

	if len(args) == 0 {
		fmt.Println("No URL provided")
		return
	}

	if _, err := url.ParseRequestURI(args[0]); err != nil {
		fmt.Println("Invalid URL")
		return
	}

	scanRemoteJS(args[0], opts)
}
