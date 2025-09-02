package main

import (
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
