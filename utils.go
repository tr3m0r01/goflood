package main

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"math/rand"
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

// Advanced anti-signature #69 utility functions

// GenerateRealisticUserAgent creates diverse, realistic user agents to avoid pattern detection
func GenerateRealisticUserAgent(browserType, platform string) string {
	// Market share weighted browser versions (updated Q4 2024)
	chromeVersions := []string{"120.0.0.0", "119.0.0.0", "118.0.0.0", "117.0.0.0", "116.0.0.0"}
	firefoxVersions := []string{"120.0", "119.0", "118.0", "117.0", "116.0"}
	safariVersions := []string{"17.2", "17.1", "17.0", "16.6", "16.5"}
	edgeVersions := []string{"120.0.2210.77", "119.0.2151.97", "118.0.2088.76"}
	
	// Platform variations
	windowsVersions := []string{"10.0", "11.0"}
	macVersions := []string{"10_15_7", "13_5_2", "14_1_2"}
	
	var userAgent string
	
	switch browserType {
	case "Chrome":
		ver := chromeVersions[rand.Intn(len(chromeVersions))]
		if platform == "Windows" {
			winVer := windowsVersions[rand.Intn(len(windowsVersions))]
			userAgent = fmt.Sprintf("Mozilla/5.0 (Windows NT %s; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s Safari/537.36", winVer, ver)
		} else if platform == "Mac" {
			macVer := macVersions[rand.Intn(len(macVersions))]
			userAgent = fmt.Sprintf("Mozilla/5.0 (Macintosh; Intel Mac OS X %s) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s Safari/537.36", macVer, ver)
		} else { // Linux
			userAgent = fmt.Sprintf("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s Safari/537.36", ver)
		}
	case "Firefox":
		ver := firefoxVersions[rand.Intn(len(firefoxVersions))]
		if platform == "Windows" {
			winVer := windowsVersions[rand.Intn(len(windowsVersions))]
			userAgent = fmt.Sprintf("Mozilla/5.0 (Windows NT %s; Win64; x64; rv:109.0) Gecko/20100101 Firefox/%s", winVer, ver)
		} else if platform == "Mac" {
			macVer := macVersions[rand.Intn(len(macVersions))]
			userAgent = fmt.Sprintf("Mozilla/5.0 (Macintosh; Intel Mac OS X %s) Gecko/20100101 Firefox/%s", macVer, ver)
		} else {
			userAgent = fmt.Sprintf("Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/%s", ver)
		}
	case "Safari":
		ver := safariVersions[rand.Intn(len(safariVersions))]
		macVer := macVersions[rand.Intn(len(macVersions))]
		// Safari version mapping
		safariMapping := map[string]string{
			"17.2": "605.1.15",
			"17.1": "605.1.15", 
			"17.0": "605.1.15",
			"16.6": "605.1.15",
			"16.5": "605.1.15",
		}
		webkitVer := safariMapping[ver]
		userAgent = fmt.Sprintf("Mozilla/5.0 (Macintosh; Intel Mac OS X %s) AppleWebKit/%s (KHTML, like Gecko) Version/%s Safari/%s", macVer, webkitVer, ver, webkitVer)
	case "Edge":
		ver := edgeVersions[rand.Intn(len(edgeVersions))]
		chromeVer := chromeVersions[0] // Edge uses Chrome engine
		winVer := windowsVersions[rand.Intn(len(windowsVersions))]
		userAgent = fmt.Sprintf("Mozilla/5.0 (Windows NT %s; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s Safari/537.36 Edg/%s", winVer, chromeVer, ver)
	default:
		// Default to Chrome as most common
		return GenerateRealisticUserAgent("Chrome", platform)
	}
	
	return userAgent
}

// GenerateSecChUa creates realistic Sec-CH-UA headers for Chromium browsers
func GenerateSecChUa(browserType string, version string) string {
	// Extract major version
	majorVersion := strings.Split(version, ".")[0]
	
	switch browserType {
	case "Chrome":
		return fmt.Sprintf(`"Not_A Brand";v="8", "Chromium";v="%s", "Google Chrome";v="%s"`, majorVersion, majorVersion)
	case "Edge":
		return fmt.Sprintf(`"Not_A Brand";v="8", "Chromium";v="%s", "Microsoft Edge";v="%s"`, majorVersion, majorVersion)
	default:
		return "" // Firefox and Safari don't send this header
	}
}

// GenerateAcceptLanguage creates realistic Accept-Language headers with quality values
func GenerateAcceptLanguage(primary string) string {
	// Common language combinations with realistic quality values
	langPatterns := map[string][]string{
		"en-US": {"en-US,en;q=0.9", "en-US,en;q=0.9,es;q=0.8", "en-US,en;q=0.9,fr;q=0.7"},
		"en-GB": {"en-GB,en;q=0.9", "en-GB,en;q=0.9,en-US;q=0.8", "en-GB,en-US;q=0.9,en;q=0.8"},
		"es-ES": {"es-ES,es;q=0.9", "es-ES,es;q=0.9,en;q=0.8", "es-ES,es;q=0.9,ca;q=0.8,en;q=0.7"},
		"fr-FR": {"fr-FR,fr;q=0.9", "fr-FR,fr;q=0.9,en;q=0.8", "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7"},
		"de-DE": {"de-DE,de;q=0.9", "de-DE,de;q=0.9,en;q=0.8", "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7"},
		"ja-JP": {"ja-JP,ja;q=0.9", "ja-JP,ja;q=0.9,en;q=0.8", "ja-JP,ja;q=0.9,en-US;q=0.8,en;q=0.7"},
		"zh-CN": {"zh-CN,zh;q=0.9", "zh-CN,zh;q=0.9,en;q=0.8", "zh-CN,zh;q=0.9,zh-TW;q=0.8,en;q=0.7"},
	}
	
	if patterns, exists := langPatterns[primary]; exists {
		return patterns[rand.Intn(len(patterns))]
	}
	
	// Default to English variants
	return langPatterns["en-US"][rand.Intn(len(langPatterns["en-US"]))]
}

// GenerateRealisticTimingPattern creates human-like request timing intervals
func GenerateRealisticTimingPattern() time.Duration {
	// Human behavior patterns (in milliseconds)
	patterns := []struct {
		min, max int
		weight   float32
	}{
		{100, 500, 0.1},     // Very fast clicking (10%)
		{500, 2000, 0.4},    // Normal browsing (40%)
		{2000, 5000, 0.3},   // Reading content (30%)
		{5000, 15000, 0.15}, // Detailed reading (15%)
		{15000, 60000, 0.05}, // Away from screen (5%)
	}
	
	randVal := rand.Float32()
	cumWeight := float32(0)
	
	for _, p := range patterns {
		cumWeight += p.weight
		if randVal <= cumWeight {
			return time.Duration(RandomInt(p.min, p.max)) * time.Millisecond
		}
	}
	
	return time.Duration(RandomInt(500, 2000)) * time.Millisecond
}

// GenerateSessionFingerprint creates a unique but consistent session identifier
func GenerateSessionFingerprint(proxyAddr string, timestamp int64) string {
	// Create a hash-based fingerprint that looks like a real session ID
	data := fmt.Sprintf("%s-%d-%d", proxyAddr, timestamp, rand.Int63())
	hash := md5.Sum([]byte(data))
	hashStr := hex.EncodeToString(hash[:])
	
	// Format to look like common session ID patterns
	formats := []string{
		fmt.Sprintf("JSESSIONID=%s", hashStr[:32]),
		fmt.Sprintf("PHPSESSID=%s", hashStr[:26]),
		fmt.Sprintf("ASP.NET_SessionId=%s", hashStr[:24]),
		fmt.Sprintf("_session_id=%s", hashStr[:32]),
		fmt.Sprintf("sid=%s", hashStr[:16]),
	}
	
	return formats[rand.Intn(len(formats))]
}

// SimulateViewportHeaders generates realistic viewport-related headers
func SimulateViewportHeaders() map[string]string {
	// Common screen resolutions and viewport sizes
	viewports := []struct {
		width, height int
		dpr           float32 // device pixel ratio
	}{
		{1920, 1080, 1.0}, // Full HD
		{1366, 768, 1.0},  // Common laptop
		{1440, 900, 2.0},  // Retina display
		{2560, 1440, 1.0}, // 2K display
		{3840, 2160, 1.5}, // 4K display
	}
	
	vp := viewports[rand.Intn(len(viewports))]
	
	headers := make(map[string]string)
	headers["Sec-CH-Viewport-Width"] = fmt.Sprintf("%d", vp.width)
	headers["Sec-CH-Viewport-Height"] = fmt.Sprintf("%d", vp.height)
	headers["Sec-CH-DPR"] = fmt.Sprintf("%.1f", vp.dpr)
	
	return headers
}
