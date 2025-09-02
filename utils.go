package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"
)

type Cookie struct {
	Name     string
	Value    string
	Expires  time.Time
	Path     string
	Domain   string
	HttpOnly bool
	Secure   bool
	SameSite string
}

// Enhanced proxy characteristics for anti-detection
type ProxyCharacteristics struct {
	Fingerprint    string
	ASNType        string
	Region         string
	ISP            string
	Reliability    float64
	Latency        time.Duration
	Bandwidth      int // Mbps
	LastSeen       time.Time
	SuccessRate    float64
}


func RandomInt(min, max int) int {
	return rand.Intn(max-min+1) + min
}

func RandomElement(elements []string) string {
	return elements[rand.Intn(len(elements))]
}

func RandomString(length int) string {
	charset := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	var sb strings.Builder
	for i := 0; i < length; i++ {
		sb.WriteByte(charset[rand.Intn(len(charset))])
	}
	return sb.String()
}

// Generate realistic tracking IDs that mimic legitimate web applications
func GenerateTrackingID(prefix string) string {
	patterns := []func(string) string{
		// Google Analytics style
		func(p string) string {
			return fmt.Sprintf("GA1.2.%d.%d", rand.Int63n(999999999), time.Now().Unix()-rand.Int63n(86400))
		},
		// Facebook pixel style
		func(p string) string {
			return fmt.Sprintf("fb.1.%d.%d", time.Now().Unix()*1000, rand.Int63n(999999999))
		},
		// Generic tracking ID
		func(p string) string {
			return fmt.Sprintf("%s_%d_%s", p, time.Now().Unix(), RandomString(8))
		},
		// UUID-like tracking
		func(p string) string {
			return fmt.Sprintf("%s-%s-%s-%s-%s", 
				RandomString(8), RandomString(4), RandomString(4), 
				RandomString(4), RandomString(12))
		},
	}
	return patterns[rand.Intn(len(patterns))](prefix)
}

// Simulate realistic browser cache-busting parameters
func GenerateCacheBuster() string {
	types := []string{
		fmt.Sprintf("v=%d", time.Now().Unix()),
		fmt.Sprintf("_=%d", time.Now().UnixMilli()),
		fmt.Sprintf("cb=%s", RandomString(8)),
		fmt.Sprintf("nocache=%d", rand.Int63n(999999)),
		fmt.Sprintf("t=%d&r=%s", time.Now().Unix(), RandomString(4)),
		fmt.Sprintf("build=%d", rand.Int63n(9999)),
	}
	return types[rand.Intn(len(types))]
}

// Generate realistic referer URLs that don't look like bot traffic
func GenerateRealisticReferer(host string) string {
	referers := []string{
		fmt.Sprintf("https://www.google.com/search?q=%s", RandomString(6)),
		fmt.Sprintf("https://www.bing.com/search?q=%s", RandomString(5)),
		fmt.Sprintf("https://%s/", host),
		fmt.Sprintf("https://%s/index.html", host),
		fmt.Sprintf("https://%s/home", host),
		fmt.Sprintf("https://%s/products", host),
		fmt.Sprintf("https://duckduckgo.com/?q=%s", RandomString(7)),
		fmt.Sprintf("https://search.yahoo.com/search?p=%s", RandomString(6)),
	}
	return referers[rand.Intn(len(referers))]
}

// Generate fingerprint-resistant headers that avoid bot detection
func GenerateAntiDetectionHeaders() map[string]string {
	headers := make(map[string]string)
	
	// Randomly include headers that real browsers sometimes send
	if rand.Float32() < 0.3 {
		headers["dnt"] = "1"
	}
	
	if rand.Float32() < 0.15 {
		headers["pragma"] = "no-cache"
	}
	
	if rand.Float32() < 0.1 {
		headers["cache-control"] = "no-cache"
	}
	
	// Viewport hints (Chrome specific)
	if rand.Float32() < 0.4 {
		headers["viewport-width"] = strconv.Itoa(rand.Intn(800) + 1200) // 1200-2000px
	}
	
	// Device memory hints
	if rand.Float32() < 0.3 {
		memory := []string{"0.25", "0.5", "1", "2", "4", "8"}
		headers["device-memory"] = memory[rand.Intn(len(memory))]
	}
	
	return headers
}

// Simulate realistic network timing patterns
func SimulateNetworkDelay(baseLatency time.Duration) {
	// Add realistic network jitter
	jitter := time.Duration(rand.Intn(50)-25) * time.Millisecond // ±25ms jitter
	delay := baseLatency + jitter
	
	// Ensure minimum realistic delay
	if delay < 5*time.Millisecond {
		delay = 5 * time.Millisecond
	}
	
	time.Sleep(delay)
}

// Generate realistic IP-based characteristics for ASN simulation
func GenerateASNCharacteristics(proxyAddr string) map[string]interface{} {
	// Hash the proxy address for consistent characteristics
	h := sha256.New()
	h.Write([]byte(proxyAddr))
	hash := hex.EncodeToString(h.Sum(nil))
	
	// Use hash to generate consistent but varied characteristics
	seed := int64(0)
	for i := 0; i < 8; i++ {
		if i < len(hash) {
			seed += int64(hash[i])
		}
	}
	r := rand.New(rand.NewSource(seed))
	
	characteristics := make(map[string]interface{})
	
	// Simulate different ASN types
	asnTypes := []string{"residential", "datacenter", "mobile", "university", "corporate"}
	characteristics["asn_type"] = asnTypes[r.Intn(len(asnTypes))]
	
	// Simulate geographic regions
	regions := []string{"US-East", "US-West", "EU-West", "EU-East", "APAC-North", "APAC-South"}
	characteristics["region"] = regions[r.Intn(len(regions))]
	
	// Simulate ISP characteristics
	isps := []string{"Comcast", "Verizon", "AT&T", "Deutsche Telekom", "Orange", "Vodafone"}
	characteristics["isp"] = isps[r.Intn(len(isps))]
	
	return characteristics
}

func ParseCookies(raw_cookies []string) ([]Cookie, error) {
	var cookies []Cookie

	for _, raw_cookie := range raw_cookies {
		cookie := Cookie{}
		parts := strings.Split(raw_cookie, ";")

		name_value := strings.Split(parts[0], "=")
		if len(name_value) == 2 {
			cookie.Name = name_value[0]
			cookie.Value = name_value[1]
		}

		for _, part := range parts[1:] {
			part = strings.TrimSpace(part)
			// fmt.Printf("part: %s\n", part)
			switch {
			case strings.HasPrefix(part, "Expires="):
				expiryStr := strings.TrimPrefix(part, "Expires=")
				expiryTime, err := ParseExpiry(expiryStr)
				if err != nil {
					// fmt.Println("error parsing cookie:", err)
					return cookies, fmt.Errorf("invalid expiry date format: %s", err.Error())
				}
				cookie.Expires = expiryTime
				// cookie.Expires = strings.TrimPrefix(part, "Expires=")
			case strings.HasPrefix(part, "Path="):
				cookie.Path = strings.TrimPrefix(part, "Path=")
			case strings.HasPrefix(part, "Domain="):
				cookie.Domain = strings.TrimPrefix(part, "Domain=")
			case strings.EqualFold(part, "HttpOnly"):
				cookie.HttpOnly = true
			}
		}

		cookies = append(cookies, cookie)
	}

	return cookies, nil
}

func FormatCookies(cookies []Cookie) string {
	var cookieHeader string
	for _, cookie := range cookies {
		if cookieHeader != "" {
			cookieHeader += "; "
		}
		cookieHeader += fmt.Sprintf("%s=%s", cookie.Name, cookie.Value)
	}

	return cookieHeader
}

func ParseExpiry(expiry string) (time.Time, error) {
	expiry_time, err := time.Parse(time.RFC1123, expiry)
	if err == nil {
		return expiry_time, nil
	}

	expiry = strings.Replace(expiry, "-", " ", -1)
	// fmt.Printf("expiry: %s\n", expiry)
	expiry_time, err = time.Parse(time.RFC1123, expiry)
	if err != nil {
		return time.Time{}, err
	}

	return expiry_time, nil
}

func UpdateCookies(initial_cookies map[string]Cookie, new_cookies []Cookie) map[string]Cookie {
	for _, new_cookie := range new_cookies {
		if existingCookie, exists := initial_cookies[new_cookie.Name]; exists {
			if new_cookie.Expires.After(existingCookie.Expires) {
				initial_cookies[new_cookie.Name] = new_cookie
			}
		} else {
			initial_cookies[new_cookie.Name] = new_cookie
		}
	}

	return initial_cookies
}

// Generate realistic session cookies that mimic legitimate web applications
func GenerateSessionCookies() map[string]string {
	cookies := make(map[string]string)
	
	// Common session cookie names used by real applications
	sessionNames := []string{"PHPSESSID", "JSESSIONID", "ASP.NET_SessionId", "session_id", "sid"}
	cookies[sessionNames[rand.Intn(len(sessionNames))]] = RandomString(26 + rand.Intn(10))
	
	// CSRF protection tokens
	csrfNames := []string{"_csrf", "csrf_token", "XSRF-TOKEN", "__RequestVerificationToken"}
	cookies[csrfNames[rand.Intn(len(csrfNames))]] = RandomString(32 + rand.Intn(32))
	
	// Analytics cookies (sometimes present)
	if rand.Float32() < 0.4 {
		cookies["_ga"] = GenerateTrackingID("GA")
		cookies["_gid"] = GenerateTrackingID("GA")
	}
	
	// User preference cookies
	if rand.Float32() < 0.3 {
		languages := []string{"en", "th", "ja", "zh", "ko", "es", "fr", "de"}
		cookies["lang"] = languages[rand.Intn(len(languages))]
	}
	
	// Marketing/tracking cookies
	if rand.Float32() < 0.2 {
		cookies["_fbp"] = GenerateTrackingID("FB")
	}
	
	// Theme preferences
	if rand.Float32() < 0.15 {
		themes := []string{"light", "dark", "auto"}
		cookies["theme"] = themes[rand.Intn(len(themes))]
	}
	
	return cookies
}

// Validate if an IP address looks like it could be from a legitimate source
func ValidateIPLegitimacy(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	
	// Check if it's a private IP (these would be behind NAT, more legitimate)
	if parsedIP.IsPrivate() {
		return true
	}
	
	// Check for common datacenter ranges (these might be flagged)
	// This is a simplified check - real implementation would have comprehensive lists
	datacenterRanges := []string{
		"104.16.0.0/12", // Cloudflare
		"13.0.0.0/8",    // Amazon AWS
		"35.0.0.0/8",    // Google Cloud
	}
	
	for _, cidr := range datacenterRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(parsedIP) {
			return false // Likely datacenter IP
		}
	}
	
	return true // Likely legitimate residential/business IP
}
