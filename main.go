package main

import (
    "bufio"
    "fmt"
    "os"
    "os/exec"
    "strings"
)

// Function to run the 'dig +trace' command and extract nameservers
func getNameservers(domain string) ([]string, error) {
    cmd := exec.Command("dig", "+trace", domain) // Use dig +trace
    output, err := cmd.Output()
    if err != nil {
        return nil, fmt.Errorf("error running dig: %v", err) // More descriptive error
    }

    // Print raw output for debugging
    rawOutput := string(output)

    // Parse the output to extract NS records
    var nameservers []string
    scanner := bufio.NewScanner(strings.NewReader(rawOutput))
    for scanner.Scan() {
        line := scanner.Text()
        // Example of matching lines that contain NS records
        if strings.Contains(line, "NS") && strings.Contains(line, domain) {
            fields := strings.Fields(line)
            // Assuming the NS record is the last field
            ns := fields[len(fields)-1]
            nameservers = append(nameservers, ns)
        }
    }

    if err := scanner.Err(); err != nil {
        return nil, fmt.Errorf("error scanning output: %v", err)
    }

    return nameservers, nil
}

// Function to resolve domain against a specific nameserver and capture status messages
func resolveAgainstNameserver(domain, nameserver string) (string, error) {
    cmd := exec.Command("dig", "@"+nameserver, domain)
    output, err := cmd.Output()
    if err != nil {
        return "", fmt.Errorf("error running dig: %v", err) // More descriptive error
    }

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
        return match
    }
    match := extractedNS == providedNS
    return match
}

// Function to read domains from the file provided in the command-line argument
func readDomainsFromFile(filePath string) ([]string, error) {
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
    } else if strings.Contains(nameserver, "orangehost.com") {
        provider = "Orange DNS"
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
        "*.orangehost.net.",  // Example wildcard nameserver
        "ns1.orangehost.com.",   // Exact match example
        "ns2.orangehost.com.",   // Another exact match example
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
