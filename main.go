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
    cmd := exec.Command("dig", domain, "NS", "+short")
    output, err := cmd.Output()
    if err != nil {
        return nil, err
    }
    nameservers := strings.Split(strings.TrimSpace(string(output)), "\n")
    return nameservers, nil
}

// Function to resolve domain against a specific nameserver and capture status messages
func resolveAgainstNameserver(domain, nameserver string) (string, error) {
    cmd := exec.Command("dig", "@"+nameserver, domain)
    output, err := cmd.Output()
    if err != nil {
        return "", err
    }
    return string(output), nil
}

// Function to check if the output contains SERVFAIL or REFUSED
func checkForErrors(output string) bool {
    return strings.Contains(output, "SERVFAIL") || strings.Contains(output, "REFUSED")
}

// Function to check if the extracted nameserver matches a wildcard nameserver
func matchesWildcard(extractedNS, providedNS string) bool {
    // If the providedNS contains '*.', treat it as a wildcard
    if strings.HasPrefix(providedNS, "*.") {
        suffix := strings.TrimPrefix(providedNS, "*.")
        return strings.HasSuffix(extractedNS, suffix)
    }
    // If no wildcard, check for an exact match
    return extractedNS == providedNS
}

// Function to read domains from the file provided in the command-line argument
func readDomainsFromFile(filePath string) ([]string, error) {
    file, err := os.Open(filePath)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    var domains []string
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        domains = append(domains, strings.TrimSpace(scanner.Text()))
    }

    if err := scanner.Err(); err != nil {
        return nil, err
    }

    return domains, nil
}

func main() {
    // Check if a file was provided as an argument
    if len(os.Args) < 2 {
        fmt.Println("Usage: go run main.go <domains.txt>")
        return
    }

    // Get the file path from the first argument
    filePath := os.Args[1]

    // List of provided nameservers to check against (wildcards allowed)
    providedNameservers := []string{
        "*.iana-servers.net.",  // Example wildcard nameserver
        "ns1.example.com.",     // Exact match example
    }

    // Read domains from the file provided as an argument
    domains, err := readDomainsFromFile(filePath)
    if err != nil {
        fmt.Println("Error reading file:", err)
        return
    }

    // Loop through each domain from the file
    for _, domain := range domains {
        // Extract nameservers for each domain
        nameservers, err := getNameservers(domain)
        if err != nil {
            fmt.Println("Error fetching nameservers for domain", domain, ":", err)
            continue
        }

        // Check if any of the extracted nameservers match the provided wildcard nameservers
        for _, ns := range nameservers {
            for _, providedNS := range providedNameservers {
                if matchesWildcard(ns, providedNS) {
                    // Resolve the domain against the matched nameserver
                    output, err := resolveAgainstNameserver(domain, ns)
                    if err != nil {
                        fmt.Printf("Error resolving domain %s against nameserver %s: %v\n", domain, ns, err)
                        continue
                    }

                    // Check for SERVFAIL or REFUSED and alert if found
                    if checkForErrors(output) {
                        fmt.Printf("ALERT: Domain %s, Nameserver %s returned SERVFAIL or REFUSED. Potential vulnerability detected!\n", domain, ns)
                    }
                }
            }
        }
    }
}
