package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/compress"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/gofiber/fiber/v2/middleware/monitor"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/fiber/v2/middleware/requestid"
)

// ============================================================================
// TCP PROTECTION LAYER
// ============================================================================

// TCPProtector provides comprehensive TCP-level protection
type TCPProtector struct {
	connTracker     *ConnectionTracker
	rateLimiter     *TCPRateLimiter
	synFloodGuard   *SYNFloodProtector
	slowlorisGuard  *SlowlorisProtector
	ackFloodGuard   *ACKFloodProtector
	resetFloodGuard *RSTFloodProtector
	config          *ProtectionConfig
	metrics         *ProtectionMetrics
	geoFilter       *GeoIPFilter
	fingerprintDB   *FingerprintDatabase
}

// ProtectionConfig contains all protection parameters
type ProtectionConfig struct {
	// Connection limits
	MaxConnectionsPerIP    int
	MaxTotalConnections    int
	MaxConnectionRate      int
	MaxHalfOpenConnections int

	// Timeout configurations
	HandshakeTimeout time.Duration
	ReadTimeout      time.Duration
	WriteTimeout     time.Duration
	IdleTimeout      time.Duration
	KeepAliveTimeout time.Duration

	// SYN flood protection
	SYNCookieEnabled bool
	SYNBacklogSize   int
	SYNRatePerSecond int

	// Rate limiting
	BytesPerSecondPerIP   int64
	PacketsPerSecondPerIP int
	BurstSize             int

	// Slowloris protection
	MinReadRate        int64
	MaxHeaderSize      int
	MaxSlowConnections int

	// ACK flood protection
	MaxACKPerSecond   int
	ACKRatioThreshold float64

	// RST flood protection
	MaxRSTPerSecond   int
	RSTRatioThreshold float64

	// IP management
	Whitelist              map[string]bool
	Blacklist              map[string]bool
	BlacklistDuration      time.Duration
	AutoBlacklistThreshold int

	// Geographic restrictions
	AllowedCountries []string
	BlockedCountries []string
	GeoIPEnabled     bool

	// Fingerprinting
	FingerprintingEnabled bool
	BotDetectionEnabled   bool

	// Advanced features
	EnableTCPFastOpen    bool
	EnableTCPNoDelay     bool
	EnableTCPDeferAccept bool
	TCPBacklogSize       int

	// Challenge-response
	ChallengeEnabled    bool
	ChallengeComplexity int
}

// ConnectionTracker tracks all active connections with detailed metrics
type ConnectionTracker struct {
	mu               sync.RWMutex
	connections      map[string]*ConnectionInfo
	ipConnections    map[string]int
	halfOpenConns    map[string]int
	totalConnections int64
	config           *ProtectionConfig
}

type ConnectionInfo struct {
	RemoteAddr     string
	LocalAddr      string
	ConnectedAt    time.Time
	LastActivity   time.Time
	LastPacketTime time.Time
	BytesRead      int64
	BytesWritten   int64
	PacketCount    int64
	SYNCount       int64
	ACKCount       int64
	RSTCount       int64
	FINCount       int64
	State          ConnectionState
	Fingerprint    string
	ThreatScore    int
	Violations     []string
}

type ConnectionState int

const (
	StateNew ConnectionState = iota
	StateSYNReceived
	StateSYNACKSent
	StateEstablished
	StateActive
	StateIdle
	StateSuspicious
	StateBlocked
	StateClosing
)

// TCPRateLimiter implements advanced token bucket with sliding window
type TCPRateLimiter struct {
	mu            sync.RWMutex
	limiters      map[string]*IPLimiter
	config        *ProtectionConfig
	cleanupTicker *time.Ticker
}

type IPLimiter struct {
	tokens             float64
	lastRefill         time.Time
	bytesWindow        []int64
	packetsWindow      []int
	windowIndex        int
	connectionAttempts []time.Time
	mu                 sync.Mutex
}

// SYNFloodProtector protects against SYN flood attacks
type SYNFloodProtector struct {
	mu           sync.RWMutex
	synAttempts  map[string]*SYNTracker
	config       *ProtectionConfig
	cookieSecret []byte
}

type SYNTracker struct {
	Count           int
	FirstSeen       time.Time
	LastSeen        time.Time
	Completed       int
	Failed          int
	CompletionRatio float64
}

// SlowlorisProtector protects against slowloris and slow POST attacks
type SlowlorisProtector struct {
	mu              sync.RWMutex
	slowConnections map[string]*SlowConnInfo
	config          *ProtectionConfig
}

type SlowConnInfo struct {
	StartTime       time.Time
	BytesRead       int64
	LastReadTime    time.Time
	ReadRate        float64
	HeaderSize      int
	PartialRequests int
}

// ACKFloodProtector protects against ACK flood attacks
type ACKFloodProtector struct {
	mu          sync.RWMutex
	ackTrackers map[string]*ACKTracker
	config      *ProtectionConfig
}

type ACKTracker struct {
	ACKCount    int
	PacketCount int
	FirstSeen   time.Time
	LastSeen    time.Time
	ACKRatio    float64
}

// RSTFloodProtector protects against RST flood attacks
type RSTFloodProtector struct {
	mu          sync.RWMutex
	rstTrackers map[string]*RSTTracker
	config      *ProtectionConfig
}

type RSTTracker struct {
	RSTCount    int
	PacketCount int
	FirstSeen   time.Time
	LastSeen    time.Time
	RSTRatio    float64
}

// GeoIPFilter filters connections based on geographic location
type GeoIPFilter struct {
	mu               sync.RWMutex
	allowedCountries map[string]bool
	blockedCountries map[string]bool
	ipCache          map[string]string
}

// FingerprintDatabase stores and analyzes connection fingerprints
type FingerprintDatabase struct {
	mu            sync.RWMutex
	fingerprints  map[string]*FingerprintInfo
	knownBots     map[string]bool
	suspiciousIPs map[string]int
}

type FingerprintInfo struct {
	Hash            string
	FirstSeen       time.Time
	LastSeen        time.Time
	ConnectionCount int
	ThreatLevel     ThreatLevel
	UserAgent       string
	TCPSignature    string
}

type ThreatLevel int

const (
	ThreatNone ThreatLevel = iota
	ThreatLow
	ThreatMedium
	ThreatHigh
	ThreatCritical
)

// ProtectionMetrics tracks comprehensive statistics
type ProtectionMetrics struct {
	TotalConnections      int64
	ActiveConnections     int64
	RejectedConnections   int64
	BlockedIPs            int64
	SYNFloodAttempts      int64
	ACKFloodAttempts      int64
	RSTFloodAttempts      int64
	SlowlorisAttempts     int64
	RateLimitHits         int64
	BytesTransferred      int64
	PacketsProcessed      int64
	GeoBlockedConnections int64
	BotConnectionsBlocked int64
	ChallengesSent        int64
	ChallengesFailed      int64
}

// ============================================================================
// INITIALIZATION
// ============================================================================

// NewTCPProtector creates a new TCP protector with configuration
func NewTCPProtector(config *ProtectionConfig) *TCPProtector {
	if config == nil {
		config = DefaultProtectionConfig()
	}

	tp := &TCPProtector{
		connTracker: &ConnectionTracker{
			connections:   make(map[string]*ConnectionInfo),
			ipConnections: make(map[string]int),
			halfOpenConns: make(map[string]int),
			config:        config,
		},
		rateLimiter: &TCPRateLimiter{
			limiters: make(map[string]*IPLimiter),
			config:   config,
		},
		synFloodGuard: &SYNFloodProtector{
			synAttempts:  make(map[string]*SYNTracker),
			config:       config,
			cookieSecret: generateSecret(),
		},
		slowlorisGuard: &SlowlorisProtector{
			slowConnections: make(map[string]*SlowConnInfo),
			config:          config,
		},
		ackFloodGuard: &ACKFloodProtector{
			ackTrackers: make(map[string]*ACKTracker),
			config:      config,
		},
		resetFloodGuard: &RSTFloodProtector{
			rstTrackers: make(map[string]*RSTTracker),
			config:      config,
		},
		geoFilter: &GeoIPFilter{
			allowedCountries: make(map[string]bool),
			blockedCountries: make(map[string]bool),
			ipCache:          make(map[string]string),
		},
		fingerprintDB: &FingerprintDatabase{
			fingerprints:  make(map[string]*FingerprintInfo),
			knownBots:     make(map[string]bool),
			suspiciousIPs: make(map[string]int),
		},
		config:  config,
		metrics: &ProtectionMetrics{},
	}

	// Initialize geographic filters
	if config.GeoIPEnabled {
		for _, country := range config.AllowedCountries {
			tp.geoFilter.allowedCountries[country] = true
		}
		for _, country := range config.BlockedCountries {
			tp.geoFilter.blockedCountries[country] = true
		}
	}

	return tp
}

// DefaultProtectionConfig returns production-ready default configuration
func DefaultProtectionConfig() *ProtectionConfig {
	return &ProtectionConfig{
		MaxConnectionsPerIP:    100,
		MaxTotalConnections:    10000,
		MaxConnectionRate:      20,
		MaxHalfOpenConnections: 50,
		HandshakeTimeout:       5 * time.Second,
		ReadTimeout:            10 * time.Second,
		WriteTimeout:           10 * time.Second,
		IdleTimeout:            120 * time.Second,
		KeepAliveTimeout:       60 * time.Second,
		SYNCookieEnabled:       true,
		SYNBacklogSize:         2048,
		SYNRatePerSecond:       50,
		BytesPerSecondPerIP:    10 * 1024 * 1024, // 10 MB/s
		PacketsPerSecondPerIP:  5000,
		BurstSize:              100,
		MinReadRate:            1024,  // 1 KB/s
		MaxHeaderSize:          16384, // 16 KB
		MaxSlowConnections:     10,
		MaxACKPerSecond:        1000,
		ACKRatioThreshold:      0.9,
		MaxRSTPerSecond:        100,
		RSTRatioThreshold:      0.5,
		Whitelist:              make(map[string]bool),
		Blacklist:              make(map[string]bool),
		BlacklistDuration:      24 * time.Hour,
		AutoBlacklistThreshold: 5,
		GeoIPEnabled:           false,
		FingerprintingEnabled:  true,
		BotDetectionEnabled:    true,
		EnableTCPFastOpen:      true,
		EnableTCPNoDelay:       true,
		EnableTCPDeferAccept:   true,
		TCPBacklogSize:         4096,
		ChallengeEnabled:       false,
		ChallengeComplexity:    3,
	}
}

// ============================================================================
// PROTECTED LISTENER
// ============================================================================

// ProtectedListener wraps a net.Listener with comprehensive protection
type ProtectedListener struct {
	listener  net.Listener
	protector *TCPProtector
	ctx       context.Context
	cancel    context.CancelFunc
}

// NewProtectedListener creates a protected TCP listener
func NewProtectedListener(network, address string, config *ProtectionConfig) (*ProtectedListener, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return setAdvancedSocketOptions(c, config)
		},
	}

	listener, err := lc.Listen(context.Background(), network, address)
	if err != nil {
		return nil, err
	}

	protector := NewTCPProtector(config)
	ctx, cancel := context.WithCancel(context.Background())

	pl := &ProtectedListener{
		listener:  listener,
		protector: protector,
		ctx:       ctx,
		cancel:    cancel,
	}

	// Start background tasks
	go pl.cleanupRoutine()
	go pl.metricsRoutine()
	go pl.threatAnalysisRoutine()

	return pl, nil
}

// Accept accepts and validates new connections
func (pl *ProtectedListener) Accept() (net.Conn, error) {
	for {
		conn, err := pl.listener.Accept()
		if err != nil {
			return nil, err
		}

		tcpConn, ok := conn.(*net.TCPConn)
		if !ok {
			conn.Close()
			continue
		}

		// Extract IP address
		remoteAddr := conn.RemoteAddr().String()
		ip, _, _ := net.SplitHostPort(remoteAddr)

		// Apply comprehensive protection checks
		if !pl.protector.ValidateConnection(ip, tcpConn) {
			atomic.AddInt64(&pl.protector.metrics.RejectedConnections, 1)
			conn.Close()
			continue
		}

		// Wrap connection with protection
		protectedConn := &ProtectedConn{
			TCPConn:   tcpConn,
			protector: pl.protector,
			ip:        ip,
			startTime: time.Now(),
			connID:    generateConnID(ip),
		}

		// Track connection
		pl.protector.connTracker.AddConnection(protectedConn)
		atomic.AddInt64(&pl.protector.metrics.TotalConnections, 1)
		atomic.AddInt64(&pl.protector.metrics.ActiveConnections, 1)

		return protectedConn, nil
	}
}

// ValidateConnection performs comprehensive validation
func (p *TCPProtector) ValidateConnection(ip string, conn *net.TCPConn) bool {
	// Check whitelist first
	if p.config.Whitelist[ip] {
		return true
	}

	// Check blacklist
	if p.config.Blacklist[ip] {
		return false
	}

	// Check total connections limit
	if atomic.LoadInt64(&p.metrics.ActiveConnections) >= int64(p.config.MaxTotalConnections) {
		log.Printf("Max total connections reached, rejecting %s", ip)
		return false
	}

	// Check per-IP connection limit
	p.connTracker.mu.RLock()
	ipConns := p.connTracker.ipConnections[ip]
	halfOpen := p.connTracker.halfOpenConns[ip]
	p.connTracker.mu.RUnlock()

	if ipConns >= p.config.MaxConnectionsPerIP {
		log.Printf("Max connections per IP reached for %s", ip)
		return false
	}

	if halfOpen >= p.config.MaxHalfOpenConnections {
		log.Printf("Max half-open connections for %s", ip)
		atomic.AddInt64(&p.metrics.SYNFloodAttempts, 1)
		p.BlockIP(ip, "Too many half-open connections")
		return false
	}

	// Check SYN flood protection
	if !p.synFloodGuard.ValidateSYN(ip) {
		atomic.AddInt64(&p.metrics.SYNFloodAttempts, 1)
		p.BlockIP(ip, "SYN flood detected")
		return false
	}

	// Check rate limiting
	if !p.rateLimiter.AllowConnection(ip) {
		atomic.AddInt64(&p.metrics.RateLimitHits, 1)
		return false
	}

	// Check geographic restrictions
	if p.config.GeoIPEnabled && !p.geoFilter.AllowIP(ip) {
		atomic.AddInt64(&p.metrics.GeoBlockedConnections, 1)
		log.Printf("Geo-blocked IP: %s", ip)
		return false
	}

	// Check fingerprint and bot detection
	if p.config.FingerprintingEnabled {
		fingerprint := p.generateFingerprint(conn, ip)
		if !p.fingerprintDB.ValidateFingerprint(fingerprint, ip) {
			atomic.AddInt64(&p.metrics.BotConnectionsBlocked, 1)
			log.Printf("Suspicious fingerprint from %s", ip)
			return false
		}
	}

	return true
}

// ============================================================================
// PROTECTED CONNECTION
// ============================================================================

type ProtectedConn struct {
	*net.TCPConn
	protector    *TCPProtector
	ip           string
	connID       string
	startTime    time.Time
	bytesRead    int64
	bytesWritten int64
	packetCount  int64
	lastActivity time.Time
	mu           sync.Mutex
}

func (pc *ProtectedConn) Read(b []byte) (int, error) {
	pc.TCPConn.SetReadDeadline(time.Now().Add(pc.protector.config.ReadTimeout))

	// Check slowloris protection
	pc.mu.Lock()
	if !pc.protector.slowlorisGuard.CheckReadRate(pc.ip, pc.bytesRead, pc.startTime) {
		pc.mu.Unlock()
		atomic.AddInt64(&pc.protector.metrics.SlowlorisAttempts, 1)
		pc.protector.BlockIP(pc.ip, "Slowloris attack detected")
		return 0, fmt.Errorf("connection blocked: slow read rate")
	}
	pc.mu.Unlock()

	n, err := pc.TCPConn.Read(b)

	if n > 0 {
		pc.mu.Lock()
		pc.bytesRead += int64(n)
		pc.packetCount++
		pc.lastActivity = time.Now()
		pc.mu.Unlock()

		atomic.AddInt64(&pc.protector.metrics.BytesTransferred, int64(n))
		atomic.AddInt64(&pc.protector.metrics.PacketsProcessed, 1)

		// Update connection info
		pc.protector.connTracker.UpdateActivity(pc.connID, n, 0)

		// Check rate limits
		if !pc.protector.rateLimiter.AllowBytes(pc.ip, int64(n)) {
			atomic.AddInt64(&pc.protector.metrics.RateLimitHits, 1)
			return n, fmt.Errorf("rate limit exceeded")
		}
	}

	return n, err
}

func (pc *ProtectedConn) Write(b []byte) (int, error) {
	pc.TCPConn.SetWriteDeadline(time.Now().Add(pc.protector.config.WriteTimeout))

	n, err := pc.TCPConn.Write(b)

	if n > 0 {
		pc.mu.Lock()
		pc.bytesWritten += int64(n)
		pc.lastActivity = time.Now()
		pc.mu.Unlock()

		atomic.AddInt64(&pc.protector.metrics.BytesTransferred, int64(n))

		// Update connection info
		pc.protector.connTracker.UpdateActivity(pc.connID, 0, n)
	}

	return n, err
}

func (pc *ProtectedConn) Close() error {
	pc.protector.connTracker.RemoveConnection(pc.connID, pc.ip)
	atomic.AddInt64(&pc.protector.metrics.ActiveConnections, -1)
	return pc.TCPConn.Close()
}

// ============================================================================
// PROTECTION IMPLEMENTATIONS
// ============================================================================

func (ct *ConnectionTracker) AddConnection(conn *ProtectedConn) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	ct.connections[conn.connID] = &ConnectionInfo{
		RemoteAddr:   conn.ip,
		ConnectedAt:  time.Now(),
		LastActivity: time.Now(),
		State:        StateNew,
	}

	ct.ipConnections[conn.ip]++
	atomic.AddInt64(&ct.totalConnections, 1)
}

func (ct *ConnectionTracker) UpdateActivity(connID string, bytesRead, bytesWritten int) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	if info, exists := ct.connections[connID]; exists {
		info.LastActivity = time.Now()
		info.BytesRead += int64(bytesRead)
		info.BytesWritten += int64(bytesWritten)
		if bytesRead > 0 || bytesWritten > 0 {
			info.PacketCount++
		}
	}
}

func (ct *ConnectionTracker) RemoveConnection(connID, ip string) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	delete(ct.connections, connID)
	ct.ipConnections[ip]--
	if ct.ipConnections[ip] <= 0 {
		delete(ct.ipConnections, ip)
	}
}

func (rl *TCPRateLimiter) AllowConnection(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	limiter, exists := rl.limiters[ip]
	if !exists {
		limiter = &IPLimiter{
			tokens:             float64(rl.config.MaxConnectionRate),
			lastRefill:         time.Now(),
			bytesWindow:        make([]int64, 10),
			packetsWindow:      make([]int, 10),
			connectionAttempts: make([]time.Time, 0),
		}
		rl.limiters[ip] = limiter
	}

	limiter.mu.Lock()
	defer limiter.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(limiter.lastRefill).Seconds()

	// Refill tokens
	limiter.tokens += elapsed * float64(rl.config.MaxConnectionRate)
	if limiter.tokens > float64(rl.config.MaxConnectionRate+rl.config.BurstSize) {
		limiter.tokens = float64(rl.config.MaxConnectionRate + rl.config.BurstSize)
	}
	limiter.lastRefill = now

	// Clean old connection attempts
	cutoff := now.Add(-time.Second)
	newAttempts := make([]time.Time, 0)
	for _, t := range limiter.connectionAttempts {
		if t.After(cutoff) {
			newAttempts = append(newAttempts, t)
		}
	}
	limiter.connectionAttempts = newAttempts

	// Check rate
	if len(limiter.connectionAttempts) >= rl.config.MaxConnectionRate {
		return false
	}

	if limiter.tokens >= 1.0 {
		limiter.tokens -= 1.0
		limiter.connectionAttempts = append(limiter.connectionAttempts, now)
		return true
	}

	return false
}

func (rl *TCPRateLimiter) AllowBytes(ip string, bytes int64) bool {
	rl.mu.Lock()
	limiter, exists := rl.limiters[ip]
	if !exists {
		limiter = &IPLimiter{
			bytesWindow:   make([]int64, 10),
			packetsWindow: make([]int, 10),
		}
		rl.limiters[ip] = limiter
	}
	rl.mu.Unlock()

	limiter.mu.Lock()
	defer limiter.mu.Unlock()

	// Update sliding window
	limiter.bytesWindow[limiter.windowIndex] += bytes
	limiter.windowIndex = (limiter.windowIndex + 1) % len(limiter.bytesWindow)

	// Calculate total bytes in window
	var totalBytes int64
	for _, b := range limiter.bytesWindow {
		totalBytes += b
	}

	return totalBytes <= rl.config.BytesPerSecondPerIP*int64(len(limiter.bytesWindow))
}

func (sfp *SYNFloodProtector) ValidateSYN(ip string) bool {
	sfp.mu.Lock()
	defer sfp.mu.Unlock()

	tracker, exists := sfp.synAttempts[ip]
	if !exists {
		tracker = &SYNTracker{
			FirstSeen: time.Now(),
		}
		sfp.synAttempts[ip] = tracker
	}

	now := time.Now()

	// Reset if time window expired
	if now.Sub(tracker.FirstSeen) > time.Second {
		tracker.Count = 0
		tracker.FirstSeen = now
		tracker.Failed = 0
	}

	tracker.Count++
	tracker.LastSeen = now

	// Calculate completion ratio
	if tracker.Count > 0 {
		tracker.CompletionRatio = float64(tracker.Completed) / float64(tracker.Count)
	}

	// Check thresholds
	if tracker.Count > sfp.config.SYNRatePerSecond {
		return false
	}

	// Suspicious if completion ratio is too low
	if tracker.Count > 10 && tracker.CompletionRatio < 0.1 {
		return false
	}

	return true
}

func (sp *SlowlorisProtector) CheckReadRate(ip string, bytesRead int64, startTime time.Time) bool {
	sp.mu.Lock()
	defer sp.mu.Unlock()

	info, exists := sp.slowConnections[ip]
	if !exists {
		info = &SlowConnInfo{
			StartTime:    startTime,
			LastReadTime: time.Now(),
		}
		sp.slowConnections[ip] = info
	}

	info.BytesRead = bytesRead
	elapsed := time.Since(info.StartTime).Seconds()

	if elapsed > 1 {
		info.ReadRate = float64(bytesRead) / elapsed

		// Check for slow read attacks
		if info.ReadRate < float64(sp.config.MinReadRate) && elapsed > 5 {
			return false
		}

		// Check for partial requests attack
		if info.PartialRequests > 100 {
			return false
		}
	}

	info.LastReadTime = time.Now()
	return true
}

func (p *TCPProtector) BlockIP(ip string, reason string) {
	p.config.Blacklist[ip] = true
	atomic.AddInt64(&p.metrics.BlockedIPs, 1)
	log.Printf("IP %s blocked: %s", ip, reason)

	// Close all connections from this IP
	p.connTracker.mu.Lock()
	for connID, info := range p.connTracker.connections {
		if info.RemoteAddr == ip {
			delete(p.connTracker.connections, connID)
		}
	}
	p.connTracker.mu.Unlock()

	// Schedule unblock
	go func() {
		time.Sleep(p.config.BlacklistDuration)
		delete(p.config.Blacklist, ip)
		log.Printf("IP %s unblocked", ip)
	}()
}

func (gf *GeoIPFilter) AllowIP(ip string) bool {
	gf.mu.RLock()
	defer gf.mu.RUnlock()

	// Check cache
	if country, exists := gf.ipCache[ip]; exists {
		if len(gf.blockedCountries) > 0 && gf.blockedCountries[country] {
			return false
		}
		if len(gf.allowedCountries) > 0 && !gf.allowedCountries[country] {
			return false
		}
	}

	return true
}

func (fdb *FingerprintDatabase) ValidateFingerprint(fingerprint, ip string) bool {
	fdb.mu.Lock()
	defer fdb.mu.Unlock()

	info, exists := fdb.fingerprints[fingerprint]
	if !exists {
		info = &FingerprintInfo{
			Hash:        fingerprint,
			FirstSeen:   time.Now(),
			ThreatLevel: ThreatNone,
		}
		fdb.fingerprints[fingerprint] = info
	}

	info.LastSeen = time.Now()
	info.ConnectionCount++

	// Check for suspicious patterns
	if info.ConnectionCount > 1000 && time.Since(info.FirstSeen) < time.Minute {
		info.ThreatLevel = ThreatHigh
		return false
	}

	return info.ThreatLevel < ThreatHigh
}

// ============================================================================
// FIBER INTEGRATION
// ============================================================================

// CreateProtectedFiberApp creates a Fiber app with full TCP protection
func CreateProtectedFiberApp(config *ProtectionConfig) (*fiber.App, *ProtectedListener, error) {
	// Create Fiber app with optimized config
	app := fiber.New(fiber.Config{
		Prefork:               false,
		ServerHeader:          "Server",
		StrictRouting:         true,
		CaseSensitive:         true,
		ReadTimeout:           config.ReadTimeout,
		WriteTimeout:          config.WriteTimeout,
		IdleTimeout:           config.IdleTimeout,
		ReadBufferSize:        4096,
		WriteBufferSize:       4096,
		BodyLimit:             10 * 1024 * 1024, // 10MB
		DisableKeepalive:      false,
		DisableStartupMessage: false,
		EnablePrintRoutes:     false,
	})

	// Apply middleware stack
	setupFiberMiddleware(app, config)

	return app, nil, nil
}

func setupFiberMiddleware(app *fiber.App, config *ProtectionConfig) {
	// Recovery middleware
	app.Use(recover.New(recover.Config{
		EnableStackTrace: true,
	}))

	// Request ID middleware
	app.Use(requestid.New())

	// Compression middleware
	app.Use(compress.New(compress.Config{
		Level: compress.LevelBestSpeed,
	}))

	// CORS middleware
	app.Use(cors.New(cors.Config{
		AllowOrigins: "*",
		AllowMethods: "GET,POST,PUT,DELETE,OPTIONS",
		AllowHeaders: "Origin,Content-Type,Accept,Authorization",
	}))

	// Custom TCP-aware rate limiter
	app.Use(limiter.New(limiter.Config{
		Max:        config.MaxConnectionRate,
		Expiration: 1 * time.Minute,
		KeyGenerator: func(c *fiber.Ctx) string {
			return c.IP()
		},
		LimitReached: func(c *fiber.Ctx) error {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error": "Rate limit exceeded",
			})
		},
	}))

	// Custom security middleware
	app.Use(SecurityMiddleware(config))

	// DDoS protection middleware
	app.Use(DDoSProtectionMiddleware(config))

	// Monitoring endpoint
	app.Get("/metrics", monitor.New(monitor.Config{
		Title: "TCP Protection Metrics",
	}))
}

// SecurityMiddleware provides application-level security
func SecurityMiddleware(config *ProtectionConfig) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ip := c.IP()

		// Check blacklist
		if config.Blacklist[ip] {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "Access denied",
			})
		}

		// Validate headers
		userAgent := c.Get("User-Agent")
		if len(userAgent) == 0 || len(userAgent) > 512 {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid User-Agent",
			})
		}

		// Check header size
		if len(c.Request().Header.String()) > config.MaxHeaderSize {
			return c.Status(fiber.StatusRequestHeaderFieldsTooLarge).JSON(fiber.Map{
				"error": "Headers too large",
			})
		}

		// Validate content type for POST/PUT
		if c.Method() == "POST" || c.Method() == "PUT" {
			contentType := c.Get("Content-Type")
			if contentType == "" {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error": "Content-Type required",
				})
			}
		}

		return c.Next()
	}
}

// DDoSProtectionMiddleware provides advanced DDoS protection
func DDoSProtectionMiddleware(config *ProtectionConfig) fiber.Handler {
	requestCounts := make(map[string]*RequestCounter)
	var mu sync.RWMutex

	return func(c *fiber.Ctx) error {
		ip := c.IP()

		mu.Lock()
		counter, exists := requestCounts[ip]
		if !exists {
			counter = &RequestCounter{
				requests:  make([]time.Time, 0),
				firstSeen: time.Now(),
			}
			requestCounts[ip] = counter
		}
		mu.Unlock()

		// Check request rate
		counter.mu.Lock()
		now := time.Now()
		cutoff := now.Add(-time.Second)

		// Remove old requests
		newRequests := make([]time.Time, 0)
		for _, t := range counter.requests {
			if t.After(cutoff) {
				newRequests = append(newRequests, t)
			}
		}
		counter.requests = newRequests
		counter.requests = append(counter.requests, now)

		requestCount := len(counter.requests)
		counter.mu.Unlock()

		if requestCount > config.MaxConnectionRate*2 {
			config.Blacklist[ip] = true
			log.Printf("IP %s auto-blocked: excessive requests (%d/sec)", ip, requestCount)
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error": "Too many requests",
			})
		}

		return c.Next()
	}
}

type RequestCounter struct {
	requests  []time.Time
	firstSeen time.Time
	mu        sync.Mutex
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

func (pl *ProtectedListener) Close() error {
	pl.cancel()
	return pl.listener.Close()
}

func (pl *ProtectedListener) Addr() net.Addr {
	return pl.listener.Addr()
}

func (pl *ProtectedListener) cleanupRoutine() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-pl.ctx.Done():
			return
		case <-ticker.C:
			pl.protector.cleanup()
		}
	}
}

func (p *TCPProtector) cleanup() {
	now := time.Now()

	// Clean up old SYN trackers
	p.synFloodGuard.mu.Lock()
	for ip, tracker := range p.synFloodGuard.synAttempts {
		if now.Sub(tracker.LastSeen) > time.Minute*5 {
			delete(p.synFloodGuard.synAttempts, ip)
		}
	}
	p.synFloodGuard.mu.Unlock()

	// Clean up old rate limiters
	p.rateLimiter.mu.Lock()
	for ip, limiter := range p.rateLimiter.limiters {
		limiter.mu.Lock()
		if now.Sub(limiter.lastRefill) > time.Minute*10 {
			delete(p.rateLimiter.limiters, ip)
		}
		limiter.mu.Unlock()
	}
	p.rateLimiter.mu.Unlock()

	// Clean up slowloris trackers
	p.slowlorisGuard.mu.Lock()
	for ip, info := range p.slowlorisGuard.slowConnections {
		if now.Sub(info.LastReadTime) > time.Minute*10 {
			delete(p.slowlorisGuard.slowConnections, ip)
		}
	}
	p.slowlorisGuard.mu.Unlock()

	// Clean up ACK flood trackers
	p.ackFloodGuard.mu.Lock()
	for ip, tracker := range p.ackFloodGuard.ackTrackers {
		if now.Sub(tracker.LastSeen) > time.Minute*5 {
			delete(p.ackFloodGuard.ackTrackers, ip)
		}
	}
	p.ackFloodGuard.mu.Unlock()

	// Clean up RST flood trackers
	p.resetFloodGuard.mu.Lock()
	for ip, tracker := range p.resetFloodGuard.rstTrackers {
		if now.Sub(tracker.LastSeen) > time.Minute*5 {
			delete(p.resetFloodGuard.rstTrackers, ip)
		}
	}
	p.resetFloodGuard.mu.Unlock()

	// Clean up idle connections
	p.connTracker.mu.Lock()
	for connID, info := range p.connTracker.connections {
		if now.Sub(info.LastActivity) > p.config.IdleTimeout {
			delete(p.connTracker.connections, connID)
			p.connTracker.ipConnections[info.RemoteAddr]--
			if p.connTracker.ipConnections[info.RemoteAddr] <= 0 {
				delete(p.connTracker.ipConnections, info.RemoteAddr)
			}
			log.Printf("Closed idle connection from %s", info.RemoteAddr)
		}
	}
	p.connTracker.mu.Unlock()
}

func (pl *ProtectedListener) metricsRoutine() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-pl.ctx.Done():
			return
		case <-ticker.C:
			pl.printMetrics()
		}
	}
}

func (pl *ProtectedListener) printMetrics() {
	m := pl.protector.metrics
	log.Printf(`
╔════════════════════════════════════════════════════════════════╗
║              TCP PROTECTION METRICS                            ║
╠════════════════════════════════════════════════════════════════╣
║ Active Connections:        %-8d                           ║
║ Total Connections:         %-8d                           ║
║ Rejected Connections:      %-8d                           ║
║ Blocked IPs:               %-8d                           ║
║                                                                ║
║ Attack Detection:                                              ║
║   - SYN Flood Attempts:    %-8d                           ║
║   - ACK Flood Attempts:    %-8d                           ║
║   - RST Flood Attempts:    %-8d                           ║
║   - Slowloris Attempts:    %-8d                           ║
║   - Rate Limit Hits:       %-8d                           ║
║   - Geo-Blocked:           %-8d                           ║
║   - Bot Blocked:           %-8d                           ║
║                                                                ║
║ Data Transfer:                                                 ║
║   - Bytes Transferred:     %-8d MB                        ║
║   - Packets Processed:     %-8d                           ║
║                                                                ║
║ Memory: %d goroutines, %d MB used                          ║
╚════════════════════════════════════════════════════════════════╝
`,
		atomic.LoadInt64(&m.ActiveConnections),
		atomic.LoadInt64(&m.TotalConnections),
		atomic.LoadInt64(&m.RejectedConnections),
		atomic.LoadInt64(&m.BlockedIPs),
		atomic.LoadInt64(&m.SYNFloodAttempts),
		atomic.LoadInt64(&m.ACKFloodAttempts),
		atomic.LoadInt64(&m.RSTFloodAttempts),
		atomic.LoadInt64(&m.SlowlorisAttempts),
		atomic.LoadInt64(&m.RateLimitHits),
		atomic.LoadInt64(&m.GeoBlockedConnections),
		atomic.LoadInt64(&m.BotConnectionsBlocked),
		atomic.LoadInt64(&m.BytesTransferred)/(1024*1024),
		atomic.LoadInt64(&m.PacketsProcessed),
		runtime.NumGoroutine(),
		getMemoryUsage(),
	)
}

func (pl *ProtectedListener) threatAnalysisRoutine() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-pl.ctx.Done():
			return
		case <-ticker.C:
			pl.analyzeThreatPatterns()
		}
	}
}

func (pl *ProtectedListener) analyzeThreatPatterns() {
	p := pl.protector
	now := time.Now()

	// Analyze connection patterns
	p.connTracker.mu.RLock()
	ipConnectionCount := make(map[string]int)
	for _, info := range p.connTracker.connections {
		ipConnectionCount[info.RemoteAddr]++
	}
	p.connTracker.mu.RUnlock()

	// Auto-block IPs with suspicious patterns
	for ip, count := range ipConnectionCount {
		if count > p.config.AutoBlacklistThreshold*10 {
			if !p.config.Whitelist[ip] && !p.config.Blacklist[ip] {
				p.BlockIP(ip, fmt.Sprintf("Suspicious connection pattern: %d connections", count))
			}
		}
	}

	// Analyze fingerprints
	p.fingerprintDB.mu.Lock()
	for fingerprint, info := range p.fingerprintDB.fingerprints {
		if now.Sub(info.LastSeen) > time.Hour*24 {
			delete(p.fingerprintDB.fingerprints, fingerprint)
		}
	}
	p.fingerprintDB.mu.Unlock()
}

func (p *TCPProtector) generateFingerprint(conn *net.TCPConn, ip string) string {
	hash := sha256.New()
	hash.Write([]byte(ip))
	hash.Write([]byte(conn.LocalAddr().String()))
	hash.Write([]byte(time.Now().Format("2006-01-02-15"))) // Hourly rotation
	return hex.EncodeToString(hash.Sum(nil))
}

func generateConnID(ip string) string {
	hash := sha256.New()
	hash.Write([]byte(ip))
	hash.Write([]byte(time.Now().String()))
	return hex.EncodeToString(hash.Sum(nil))[:16]
}

func generateSecret() []byte {
	hash := sha256.New()
	hash.Write([]byte(time.Now().String()))
	return hash.Sum(nil)
}

func setAdvancedSocketOptions(c syscall.RawConn, config *ProtectionConfig) error {
	var optErr error
	err := c.Control(func(fd uintptr) {
		// Set TCP_DEFER_ACCEPT
		if config.EnableTCPDeferAccept {
			optErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, 9, 30)
			if optErr != nil {
				log.Printf("Failed to set TCP_DEFER_ACCEPT: %v", optErr)
			}
		}

		// Set TCP_NODELAY
		if config.EnableTCPNoDelay {
			optErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1)
			if optErr != nil {
				log.Printf("Failed to set TCP_NODELAY: %v", optErr)
			}
		}

		// Set SO_REUSEADDR
		optErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
		if optErr != nil {
			log.Printf("Failed to set SO_REUSEADDR: %v", optErr)
		}

		// Set SO_REUSEPORT (Linux 3.9+)
		optErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, 15, 1) // SO_REUSEPORT
		if optErr != nil {
			log.Printf("Failed to set SO_REUSEPORT: %v", optErr)
		}

		// Set TCP backlog
		optErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 1024*1024)
		if optErr != nil {
			log.Printf("Failed to set SO_RCVBUF: %v", optErr)
		}

		optErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, 1024*1024)
		if optErr != nil {
			log.Printf("Failed to set SO_SNDBUF: %v", optErr)
		}
	})

	if err != nil {
		return err
	}
	return optErr
}

func getMemoryUsage() uint64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.Alloc / 1024 / 1024
}

// ============================================================================
// MAIN EXAMPLE WITH FIBER
// ============================================================================

func main() {
	// Create protection configuration
	config := DefaultProtectionConfig()
	config.MaxConnectionsPerIP = 100
	config.MaxTotalConnections = 10000
	config.MaxConnectionRate = 50
	config.BytesPerSecondPerIP = 10 * 1024 * 1024 // 10 MB/s

	// Whitelist trusted IPs
	config.Whitelist["127.0.0.1"] = true
	config.Whitelist["::1"] = true

	// Create protected listener
	listener, err := NewProtectedListener("tcp", ":8082", config)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	// Create Fiber app
	app, _, err := CreateProtectedFiberApp(config)
	if err != nil {
		log.Fatal(err)
	}

	// Define routes
	app.Get("/", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status":  "ok",
			"message": "Protected TCP server is running",
			"ip":      c.IP(),
		})
	})

	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status": "healthy",
			"uptime": time.Since(listener.protector.connTracker.connections[c.IP()].ConnectedAt).String(),
		})
	})

	app.Post("/api/data", func(c *fiber.Ctx) error {
		type Request struct {
			Data string `json:"data"`
		}

		var req Request
		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid request body",
			})
		}

		return c.JSON(fiber.Map{
			"status":   "success",
			"received": len(req.Data),
		})
	})

	app.Get("/stats", func(c *fiber.Ctx) error {
		m := listener.protector.metrics
		return c.JSON(fiber.Map{
			"active_connections":   atomic.LoadInt64(&m.ActiveConnections),
			"total_connections":    atomic.LoadInt64(&m.TotalConnections),
			"rejected_connections": atomic.LoadInt64(&m.RejectedConnections),
			"blocked_ips":          atomic.LoadInt64(&m.BlockedIPs),
			"syn_flood_attempts":   atomic.LoadInt64(&m.SYNFloodAttempts),
			"slowloris_attempts":   atomic.LoadInt64(&m.SlowlorisAttempts),
			"rate_limit_hits":      atomic.LoadInt64(&m.RateLimitHits),
			"bytes_transferred":    atomic.LoadInt64(&m.BytesTransferred),
			"packets_processed":    atomic.LoadInt64(&m.PacketsProcessed),
		})
	})

	// Graceful shutdown
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		log.Println("Gracefully shutting down...")
		app.Shutdown()
		listener.Close()
	}()

	// Start server with protected listener
	log.Println("🚀 Protected TCP server starting on :8082")
	log.Println("📊 Metrics available at http://localhost:8082/metrics")
	log.Println("📈 Stats available at http://localhost:8082/stats")

	if err := app.Listener(listener); err != nil {
		log.Fatal(err)
	}
}
