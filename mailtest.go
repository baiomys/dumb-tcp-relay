package main

import (
        "crypto/tls"
        "flag"
        "fmt"
        "log"
        "math/rand"
        "net"
        "net/mail"
        "net/smtp"
        "os"
        "strings"
        "sync"
        "sync/atomic"
        "time"
)

type Config struct {
        From          string
        To            string
        Subject       string
        Server        string
        Port          int
        Messages      int
        Workers       int
        MinSize       int
        MaxSize       int
        StartTLS      bool
        StrictTLS     bool
        Verbose       bool
        LogFile       string
        RandomSubject bool
}

type Stats struct {
        Total     int32
        Success   int32
        Failed    int32
        StartTime time.Time
}

var (
        config  Config
        stats   Stats
        wg      sync.WaitGroup
        logFile *os.File
        logger  *log.Logger
)

func init() {
        flag.StringVar(&config.From, "from", "sender@example.com", "From email address")
        flag.StringVar(&config.To, "to", "recipient@example.com", "To email address")
        flag.StringVar(&config.Subject, "subject", "Test Email", "Email subject")
        flag.StringVar(&config.Server, "server", "", "SMTP server address (can be MX record, leave empty for auto MX lookup from 'to' address)")
        flag.IntVar(&config.Port, "port", 25, "SMTP server port")
        flag.IntVar(&config.Messages, "messages", 10, "Number of messages to send")
        flag.IntVar(&config.Workers, "workers", 5, "Number of concurrent workers")
        flag.IntVar(&config.MinSize, "minsize", 100, "Minimum message size in bytes")
        flag.IntVar(&config.MaxSize, "maxsize", 1024, "Maximum message size in bytes")
        flag.BoolVar(&config.StartTLS, "starttls", true, "Use STARTTLS")
        flag.BoolVar(&config.StrictTLS, "strict", false, "Enable strict TLS certificate verification (default is to skip verification)") // Changed
        flag.BoolVar(&config.Verbose, "verbose", false, "Verbose output")
        flag.StringVar(&config.LogFile, "log", "", "Log file path")
        flag.BoolVar(&config.RandomSubject, "randomsubject", false, "Use random subjects")
}

func main() {
        // Customize help output
        flag.Usage = func() {
                fmt.Fprintf(os.Stderr, "SMTP Load Testing Tool\n\n")
                fmt.Fprintf(os.Stderr, "Usage:\n  %s [options]\n\n", os.Args[0])
                fmt.Fprintf(os.Stderr, "Required Options:\n")
                fmt.Fprintf(os.Stderr, "  -from string    \tFrom email address (default \"sender@example.com\")\n")
                fmt.Fprintf(os.Stderr, "  -to string      \tTo email address (default \"recipient@example.com\")\n\n")

                fmt.Fprintf(os.Stderr, "Server Configuration:\n")
                fmt.Fprintf(os.Stderr, "  -server string  \tSMTP server (empty for MX lookup from -to domain) (default \"\")\n")
                fmt.Fprintf(os.Stderr, "  -port int       \tSMTP server port (default 25)\n")
                fmt.Fprintf(os.Stderr, "  -starttls       \tUse STARTTLS (default true)\n")
                fmt.Fprintf(os.Stderr, "  -strict         \tEnable strict TLS certificate validation (default false)\n\n")

                fmt.Fprintf(os.Stderr, "Message Options:\n")
                fmt.Fprintf(os.Stderr, "  -subject string \tEmail subject (default \"Test Email\")\n")
                fmt.Fprintf(os.Stderr, "  -randomsubject  \tAppend random numbers to subject (default false)\n")
                fmt.Fprintf(os.Stderr, "  -minsize int    \tMinimum message size in bytes (default 100)\n")
                fmt.Fprintf(os.Stderr, "  -maxsize int    \tMaximum message size in bytes (default 1024)\n\n")

                fmt.Fprintf(os.Stderr, "Load Testing:\n")
                fmt.Fprintf(os.Stderr, "  -messages int   \tNumber of messages to send (default 10)\n")
                fmt.Fprintf(os.Stderr, "  -workers int    \tConcurrent workers (default 5)\n\n")

                fmt.Fprintf(os.Stderr, "Diagnostics:\n")
                fmt.Fprintf(os.Stderr, "  -verbose        \tVerbose output (default false)\n")
                fmt.Fprintf(os.Stderr, "  -log string     \tLog file path (default \"\")\n\n")

                fmt.Fprintf(os.Stderr, "Examples:\n")
                fmt.Fprintf(os.Stderr, "  Basic test:          %s -from test@domain.com -to user@gmail.com\n", os.Args[0])
                fmt.Fprintf(os.Stderr, "  High-volume test:    %s -from test@domain.com -to user@domain.com -messages 1000 -workers 20\n", os.Args[0])
                fmt.Fprintf(os.Stderr, "  Production testing:  %s -from real@domain.com -to monitor@domain.com -server smtp.gmail.com -strict\n", os.Args[0])
        }

        if len(os.Args) == 1 {
                flag.Usage()
                os.Exit(0)
        }

        flag.Parse()
        validateConfig()

        // Initialize logging
        initLogger()

        // Resolve destination server
        resolveDestination()

        // Print configuration
        printConfig()

        // Create workers
        stats.StartTime = time.Now()
        messageChan := make(chan int, config.Messages)
        for i := 0; i < config.Workers; i++ {
                wg.Add(1)
                go worker(i+1, messageChan)
        }

        // Feed workers with messages
        for i := 0; i < config.Messages; i++ {
                messageChan <- i + 1
        }
        close(messageChan)

        // Wait for completion
        wg.Wait()

        // Print summary
        printSummary()

        // Close log file
        if logFile != nil {
                logFile.Close()
        }
}

func validateConfig() {
        if config.From == "" || config.To == "" {
                log.Fatal("From and To addresses are required")
        }

        if config.Messages < 1 {
                log.Fatal("Number of messages must be at least 1")
        }

        if config.Workers < 1 {
                log.Fatal("Number of workers must be at least 1")
        }

        if config.MinSize < 1 || config.MaxSize < 1 || config.MinSize > config.MaxSize {
                log.Fatal("Invalid message size range")
        }

        if config.Port < 1 || config.Port > 65535 {
                log.Fatal("Invalid port number")
        }
}

func initLogger() {
        if config.LogFile != "" {
                var err error
                logFile, err = os.OpenFile(config.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
                if err != nil {
                    log.Fatalf("Failed to open log file: %v", err)
                }
                logger = log.New(logFile, "", log.LstdFlags)
        } else {
                logger = log.New(os.Stdout, "", log.LstdFlags)
        }
}

func resolveDestination() {
        if config.Server == "" {
                // Case 1: No server specified - get MX from recipient's domain
                resolveMXFromRecipient()
                return
        }

        // Case 2: Server specified - try MX first
        mxRecords, err := net.LookupMX(config.Server)
        if err == nil && len(mxRecords) > 0 {
                // Found MX records - use highest priority
                config.Server = strings.TrimSuffix(mxRecords[0].Host, ".")
                logMessage(fmt.Sprintf("Using MX record for specified server: %s", config.Server))
                return
        }

        // Case 3: No MX found for specified server - verify it's a valid hostname
        _, err = net.LookupHost(config.Server)
        if err != nil {
                log.Fatalf("Specified server '%s' is neither a valid MX record nor resolvable hostname", config.Server)
        }
        logMessage(fmt.Sprintf("Using specified server directly: %s", config.Server))
}

func resolveMXFromRecipient() {
        domain := strings.Split(config.To, "@")[1]
        mxRecords, err := net.LookupMX(domain)
        if err != nil {
                log.Fatalf("MX lookup for recipient domain '%s' failed: %v", domain, err)
        }

        if len(mxRecords) == 0 {
                log.Fatalf("No MX records found for recipient domain '%s'", domain)
        }

        config.Server = strings.TrimSuffix(mxRecords[0].Host, ".")
        logMessage(fmt.Sprintf("Resolved recipient MX record: %s", config.Server))
}

func printConfig() {
        logMessage("=== Configuration ===")
        logMessage(fmt.Sprintf("From: %s", config.From))
        logMessage(fmt.Sprintf("To: %s", config.To))
        logMessage(fmt.Sprintf("Server: %s:%d", config.Server, config.Port))
        logMessage(fmt.Sprintf("Messages: %d", config.Messages))
        logMessage(fmt.Sprintf("Workers: %d", config.Workers))
        logMessage(fmt.Sprintf("Message size: %d-%d bytes", config.MinSize, config.MaxSize))
        logMessage(fmt.Sprintf("STARTTLS: %v", config.StartTLS))
        logMessage(fmt.Sprintf("Skip TLS verify: %v", !config.StrictTLS))
        logMessage("=====================")
}

func worker(id int, messages <-chan int) {
        defer wg.Done()

        for msgNum := range messages {
                subject := config.Subject
                if config.RandomSubject {
                    subject = fmt.Sprintf("%s #%d-%d", config.Subject, msgNum, id)
                }

                err := sendEmail(msgNum, subject)
                if err != nil {
                    atomic.AddInt32(&stats.Failed, 1)
                    logMessage(fmt.Sprintf("[Worker %d] Message %d failed: %v", id, msgNum, err))
                } else {
                    atomic.AddInt32(&stats.Success, 1)
                    if config.Verbose {
                        logMessage(fmt.Sprintf("[Worker %d] Message %d sent successfully", id, msgNum))
                    }
                }
                atomic.AddInt32(&stats.Total, 1)
        }
}

func sendEmail(msgNum int, subject string) error {
        // Generate random message body
        body := generateRandomBody()

        // Parse email addresses
        fromAddr, err := mail.ParseAddress(config.From)
        if err != nil {
                return fmt.Errorf("invalid From address: %v", err)
        }

        toAddr, err := mail.ParseAddress(config.To)
        if err != nil {
                return fmt.Errorf("invalid To address: %v", err)
        }

        // Connect to the server
        conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", config.Server, config.Port), 10*time.Second)
        if err != nil {
                return fmt.Errorf("connection failed: %v", err)
        }
        defer conn.Close()

        client, err := smtp.NewClient(conn, config.Server)
        if err != nil {
                return fmt.Errorf("SMTP client creation failed: %v", err)
        }
        defer client.Close()

        // STARTTLS if requested
        if config.StartTLS {
                tlsConfig := &tls.Config{
                    ServerName:         config.Server,
                    InsecureSkipVerify: !config.StrictTLS,
                }
                if err = client.StartTLS(tlsConfig); err != nil {
                    return fmt.Errorf("STARTTLS failed: %v", err)
                }
        }

        // Set sender and recipient
        if err = client.Mail(fromAddr.Address); err != nil {
                return fmt.Errorf("MAIL FROM failed: %v", err)
        }

        if err = client.Rcpt(toAddr.Address); err != nil {
                return fmt.Errorf("RCPT TO failed: %v", err)
        }

        // Send email data
        wc, err := client.Data()
        if err != nil {
                return fmt.Errorf("DATA failed: %v", err)
        }
        defer wc.Close()

        // Write email headers and body
        headers := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n",
                fromAddr.String(), toAddr.String(), subject)
        if _, err = fmt.Fprint(wc, headers); err != nil {
                return fmt.Errorf("header write failed: %v", err)
        }

        if _, err = fmt.Fprint(wc, body); err != nil {
                return fmt.Errorf("body write failed: %v", err)
        }

        return nil
}

func generateRandomBody() string {
        size := config.MinSize
        if config.MaxSize > config.MinSize {
                size = config.MinSize + rand.Intn(config.MaxSize-config.MinSize)
        }

        // Generate random text
        const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 \t\n.,!?"
        result := make([]byte, size)
        for i := range result {
                result[i] = charset[rand.Intn(len(charset))]
        }

        return string(result)
}

func logMessage(message string) {
        logger.Println(message)
}

func printSummary() {
        duration := time.Since(stats.StartTime)
        rate := float64(stats.Total) / duration.Seconds()

        logMessage("\n=== Summary ===")
        logMessage(fmt.Sprintf("Total messages: %d", stats.Total))
        logMessage(fmt.Sprintf("Successful: %d", stats.Success))
        logMessage(fmt.Sprintf("Failed: %d", stats.Failed))
        logMessage(fmt.Sprintf("Duration: %v", duration.Round(time.Second)))
        logMessage(fmt.Sprintf("Rate: %.2f messages/second", rate))
        logMessage("===============")
}
