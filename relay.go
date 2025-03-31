package main

import (
        "encoding/json"
        "errors"
        "flag"
        "fmt"
        "io"
        "net"
        "os"
        "strings"
        "sync/atomic"
        "time"
        "sync"
)

// Config represents the server configuration
type Config struct {
        ListenAddr      string   `json:"listen_addr"`      // Address to listen on
        TargetPort      string   `json:"target_port"`      // Port to forward to
        RemoteIPs       []string `json:"remote_ips"`       // List of IPs to relay to
        MXDomain        string   `json:"mx_domain"`        // Domain to lookup MX records for
        Timeout         int      `json:"timeout"`          // Connection timeout in seconds
        BufferSize      int      `json:"buffer_size"`      // Buffer size for copying data
        ResolveMX       bool     `json:"resolve_mx"`       // Whether to resolve MX records
        ResolveFreq     int      `json:"resolve_freq"`     // MX resolution frequency in minutes
        RateLimit       int      `json:"rate_limit"`       // Max connections per time window
        RateLimitWindow int      `json:"rate_limit_window"`// Time window in seconds for rate limiting
}

// TCPRelay represents the TCP relay server
type TCPRelay struct {
        config      *Config
        remoteIPs   []net.IP
        nextRemote  uint32 // for round-robin selection
        lastResolve time.Time
        log         func(string, ...interface{}) // Unified logging function
        rateLimiter *RateLimiter
}

// RateLimiter tracks connection attempts per IP
type RateLimiter struct {
        mu         sync.Mutex
        ips        map[string]rateLimitEntry
        rateLimit  int
        timeWindow time.Duration
}

type rateLimitEntry struct {
        FirstSeen   time.Time
        Connections int
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(rateLimit int, timeWindowSec int) *RateLimiter {
        return &RateLimiter{
                ips:        make(map[string]rateLimitEntry),
                rateLimit:  rateLimit,
                timeWindow: time.Duration(timeWindowSec) * time.Second,
        }
}

// Allow checks if the IP is allowed to connect
func (rl *RateLimiter) Allow(ip string) bool {
        rl.mu.Lock()
        defer rl.mu.Unlock()

        now := time.Now()
        entry, exists := rl.ips[ip]

        // If entry doesn't exist or has expired, create new entry
        if !exists || now.Sub(entry.FirstSeen) > rl.timeWindow {
                rl.ips[ip] = rateLimitEntry{
                    FirstSeen:   now,
                    Connections: 1,
                }
                return true
        }

        // Entry exists within time window
        if entry.Connections >= rl.rateLimit {
                return false
        }

        // Increment connection count
        entry.Connections++
        rl.ips[ip] = entry
        return true
}

// cleanup removes expired entries
func (rl *RateLimiter) cleanup() {
        rl.mu.Lock()
        defer rl.mu.Unlock()

        now := time.Now()
        for ip, entry := range rl.ips {
                if now.Sub(entry.FirstSeen) > rl.timeWindow {
                    delete(rl.ips, ip)
                }
        }
}

func main() {
        configPath := flag.String("c", "config.json", "Path to configuration file")
        quietMode := flag.Bool("q", false, "Enable quiet mode (suppress logs)")
        flag.Parse()

        config, err := loadConfig(*configPath)
        if err != nil {
                fmt.Printf("Error loading config: %v\n", err)
                os.Exit(1)
        }

        // Create logging function based on quiet mode
        logFunc := func(format string, v ...interface{}) {
                if !*quietMode {
                    fmt.Printf(format+"\n", v...)
                }
        }

        relay, err := NewTCPRelay(config, logFunc)
        if err != nil {
                fmt.Printf("Error creating relay: %v\n", err)
                os.Exit(1)
        }

        logFunc("Starting TCP relay server on %s, forwarding to port %s",
                config.ListenAddr, config.TargetPort)

        if err := relay.ListenAndServe(); err != nil {
                fmt.Printf("Server error: %v\n", err)
                os.Exit(1)
        }
}

func loadConfig(filename string) (*Config, error) {
        data, err := os.ReadFile(filename)
        if err != nil {
                return nil, err
        }

        var config Config
        if err := json.Unmarshal(data, &config); err != nil {
                return nil, err
        }

        // Validate configuration
        if config.ListenAddr == "" {
                return nil, errors.New("listen_addr must be specified")
        }
        if config.TargetPort == "" {
                return nil, errors.New("target_port must be specified")
        }
        if len(config.RemoteIPs) == 0 && config.MXDomain == "" {
                return nil, errors.New("either remote_ips or mx_domain must be specified")
        }
        if config.Timeout == 0 {
                config.Timeout = 30 // default to 30 seconds
        }
        if config.BufferSize == 0 {
                config.BufferSize = 32 * 1024 // default to 32KB
        }
        if config.ResolveFreq == 0 {
                config.ResolveFreq = 5 // default to 5 minutes
        }
        if config.MXDomain != "" {
                config.ResolveMX = true
        }
        if config.RateLimit == 0 {
                config.RateLimit = 100 // default rate limit
        }
        if config.RateLimitWindow == 0 {
                config.RateLimitWindow = 60 // default to 60 seconds
        }

        return &config, nil
}

func NewTCPRelay(config *Config, logFunc func(string, ...interface{})) (*TCPRelay, error) {
        relay := &TCPRelay{
                config:      config,
                log:         logFunc,
                rateLimiter: NewRateLimiter(config.RateLimit, config.RateLimitWindow),
        }

        if err := relay.resolveTargets(); err != nil {
                return nil, err
        }

        return relay, nil
}

func (r *TCPRelay) resolveTargets() error {
        var ips []net.IP

        // Add configured IPs
        for _, ipStr := range r.config.RemoteIPs {
                ip := net.ParseIP(ipStr)
                if ip == nil {
                    return fmt.Errorf("invalid IP address: %s", ipStr)
                }
                ips = append(ips, ip)
        }

        // Resolve MX records if configured
        if r.config.ResolveMX {
                mxIPs, err := r.resolveMX()
                if err != nil {
                    if len(ips) == 0 {
                        return fmt.Errorf("MX resolution failed and no fallback IPs: %v", err)
                    }
                    r.log("Warning: MX resolution failed: %v, using fallback IPs", err)
                } else {
                    ips = append(ips, mxIPs...)
                }
        }

        if len(ips) == 0 {
                return errors.New("no valid target IPs found")
        }

        r.remoteIPs = ips
        r.lastResolve = time.Now()
        r.log("Resolved %d target IPs", len(ips))
        return nil
}

func (r *TCPRelay) resolveMX() ([]net.IP, error) {
        mxRecords, err := net.LookupMX(r.config.MXDomain)
        if err != nil {
                return nil, fmt.Errorf("MX lookup failed: %v", err)
        }

        var ips []net.IP
        for _, mx := range mxRecords {
                host := strings.TrimSuffix(mx.Host, ".")
                mxIPs, err := net.LookupIP(host)
                if err != nil {
                    r.log("Warning: could not resolve MX host %s: %v", host, err)
                    continue
                }
                ips = append(ips, mxIPs...)
        }

        if len(ips) == 0 {
                return nil, errors.New("no IPs resolved from MX records")
        }

        return ips, nil
}

func (r *TCPRelay) checkRefresh() {
        if !r.config.ResolveMX {
                return
        }

        if time.Since(r.lastResolve) > time.Duration(r.config.ResolveFreq)*time.Minute {
                r.log("Refreshing MX records...")
                if err := r.resolveTargets(); err != nil {
                    r.log("Error refreshing MX records: %v", err)
                }
        }
}

func (r *TCPRelay) ListenAndServe() error {
        l, err := net.Listen("tcp", r.config.ListenAddr)
        if err != nil {
                return err
        }
        defer l.Close()

        for {
                conn, err := l.Accept()
                if err != nil {
                    r.log("Accept error: %v", err)
                    continue
                }

                // Get remote IP
                remoteAddr, _, err := net.SplitHostPort(conn.RemoteAddr().String())
                if err != nil {
                    r.log("Error parsing remote address: %v", err)
                    conn.Close()
                    continue
                }

                // Cleanup expired entries before checking rate limit
                r.rateLimiter.cleanup()

                // Check rate limit
                if !r.rateLimiter.Allow(remoteAddr) {
                    r.log("Rate limit exceeded for %s", remoteAddr)
                    conn.Close()
                    continue
                }

                go r.handleConnection(conn)
        }
}

func (r *TCPRelay) handleConnection(src net.Conn) {
        defer src.Close()

        r.checkRefresh()

        next := atomic.AddUint32(&r.nextRemote, 1)
        remoteIP := r.remoteIPs[int(next)%len(r.remoteIPs)]
        targetAddr := net.JoinHostPort(remoteIP.String(), r.config.TargetPort)

        dst, err := net.DialTimeout("tcp", targetAddr, time.Duration(r.config.Timeout)*time.Second)
        if err != nil {
                r.log("Failed to connect to remote %s: %v", targetAddr, err)
                return
        }
        defer dst.Close()

        timeout := time.Now().Add(time.Duration(r.config.Timeout) * time.Second)
        src.SetDeadline(timeout)
        dst.SetDeadline(timeout)

        r.log("Forwarding %s <-> %s", src.RemoteAddr(), targetAddr)

        // Use WaitGroup to wait for both copy directions to complete
        var wg sync.WaitGroup
        wg.Add(2)

        // Setup close channel
        closeChan := make(chan struct{}, 1)

        // Copy from source to destination
        go func() {
                defer wg.Done()
                r.copyData(dst, src, closeChan)
        }()

        // Copy from destination to source
        go func() {
                defer wg.Done()
                r.copyData(src, dst, closeChan)
        }()

        select {
                case <-closeChan:
                    src.Close()
                    dst.Close()
                case <-time.After(time.Duration(r.config.Timeout) * time.Second):
                    src.Close()
                    dst.Close()
        }

        // Wait for both copy routines to finish
        wg.Wait()
}

func (r *TCPRelay) copyData(dst net.Conn, src net.Conn, closeChan chan struct{}) {
        buf := make([]byte, r.config.BufferSize)
        _, err := io.CopyBuffer(dst, src, buf)
        if err != nil {
                if !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
                    r.log("Copy error: %v", err)
                }
        }

        // Signal that we're done and the connection should close
        select {
        case closeChan <- struct{}{}:
        default:
        }
}
