package main

import (
    "bufio"
    "fmt"
    "os"
    "os/exec"
    "strings"
)

// Function to run the 'dig' command and extract nameservers
func getNameservers(domain string) ([]string, error) {
    fmt.Printf("Running dig command for NS records on domain: %s\n", domain) // Debug info
    cmd := exec.Command("dig", domain, "NS", "+short")
    output, err := cmd.Output()
    if err != nil {
        return nil, fmt.Errorf("error running dig: %v", err) // More descriptive error
    }

    // Print raw output for debugging
    rawOutput := string(output)
    fmt.Printf("Raw output from dig for domain %s:\n%s\n", domain, rawOutput) // Debug info

    nameservers := strings.Split(strings.TrimSpace(rawOutput), "\n")
    // Filter out any empty strings that may occur
    var validNS []string
    for _, ns := range nameservers {
        if ns != "" {
            validNS = append(validNS, ns)
        }
    }

    fmt.Printf("Extracted nameservers for domain %s: %v\n", domain, validNS) // Debug info
    return validNS, nil
}

// Function to resolve domain against a specific nameserver and capture status messages
func resolveAgainstNameserver(domain, nameserver string) (string, error) {
    fmt.Printf("Resolving domain %s against nameserver %s...\n", domain, nameserver) // Debug info
    cmd := exec.Command("dig", "@"+nameserver, domain)
    output, err := cmd.Output()
    if err != nil {
        return "", fmt.Errorf("error running dig: %v", err) // More descriptive error
    }

    // Print the output for debugging purposes
    fmt.Printf("Dig output for domain %s and nameserver %s:\n%s\n", domain, nameserver, string(output))

    return string(output), nil
}

// Function to check if the output contains SERVFAIL or REFUSED
func checkForErrors(output string) bool {
    hasError := strings.Contains(output, "SERVFAIL") || strings.Contains(output, "REFUSED")
    if hasError {
        fmt.Println("Error detected: SERVFAIL or REFUSED found in output.") // Debug info
    }
    return hasError
}

// Function to check if the extracted nameserver matches a wildcard nameserver
func matchesWildcard(extractedNS, providedNS string) bool {
    if strings.HasPrefix(providedNS, "*.") {
        suffix := strings.TrimPrefix(providedNS, "*.")
        match := strings.HasSuffix(extractedNS, suffix)
        fmt.Printf("Matching extracted NS %s against wildcard NS %s: %v\n", extractedNS, providedNS, match) // Debug info
        return match
    }
    match := extractedNS == providedNS
    fmt.Printf("Exact match check: %s == %s: %v\n", extractedNS, providedNS, match) // Debug info
    return match
}

// Function to read domains from the file provided in the command-line argument
func readDomainsFromFile(filePath string) ([]string, error) {
    fmt.Printf("Reading domains from file: %s\n", filePath) // Debug info
    file, err := os.Open(filePath)
    if err != nil {
        return nil, fmt.Errorf("error opening file: %v", err) // More descriptive error
    }
    defer file.Close()

    var domains []string
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        domains = append(domains, strings.TrimSpace(scanner.Text()))
    }

    if err := scanner.Err(); err != nil {
        return nil, fmt.Errorf("error reading file: %v", err) // More descriptive error
    }

    fmt.Printf("Domains read from file: %v\n", domains) // Debug info
    return domains, nil
}

// Function to identify if a nameserver belongs to a known provider
func getDNSProvider(nameserver string) string {
    provider := "Unknown"
    if strings.Contains(nameserver, "amazonaws.com") {
        provider = "AWS Route 53"
    } else if strings.Contains(nameserver, "cloudflare.com") {
        provider = "Cloudflare"
    } else if strings.Contains(nameserver, "google.com") {
        provider = "Google Cloud DNS"
    } else if strings.Contains(nameserver, "azure-dns.com") {
        provider = "Azure DNS"
    }
    fmt.Printf("Identified provider for nameserver %s: %s\n", nameserver, provider) // Debug info
    return provider
}

func main() {
    // Check if a file was provided as an argument
    if len(os.Args) < 2 {
        fmt.Println("Usage: go run main.go <domains.txt>")
        return
    }

    filePath := os.Args[1]

    // Provided nameservers array including wildcard and exact match examples
    providedNameservers := []string{
        "*.orangehost.com.",
                                  // Example wildcard nameserver
                                 // Exact match example
                                 // Another exact match example
    }

    // Read the list of domains from the specified file
    domains, err := readDomainsFromFile(filePath)
    if err != nil {
        fmt.Println("Error reading file:", err)
        return
    }

    // Iterate through each domain and check nameservers
    for _, domain := range domains {
        nameservers, err := getNameservers(domain)
        if err != nil {
            fmt.Println("Error fetching nameservers for domain", domain, ":", err)
            continue
        }

        // Check extracted nameservers against provided nameservers
        for _, ns := range nameservers {
            for _, providedNS := range providedNameservers {
                if matchesWildcard(ns, providedNS) {
                    provider := getDNSProvider(ns)
                    fmt.Printf("Nameserver %s is hosted by %s\n", ns, provider)

                    // Resolve the domain against the matched nameserver
                    output, err := resolveAgainstNameserver(domain, ns)
                    if err != nil {
                        fmt.Printf("Error resolving domain %s against nameserver %s: %v\n", domain, ns, err)
                        continue
                    }

                    // Check for SERVFAIL or REFUSED
                    if checkForErrors(output) {
                        fmt.Printf("ALERT: Domain %s, Nameserver %s returned SERVFAIL or REFUSED. Potential vulnerability detected!\n", domain, ns)
                        if provider != "Unknown" {
                            fmt.Printf("This could be vulnerable to takeover via %s\n", provider)
                        }
                    }
                }
            }
        }
    }
}
