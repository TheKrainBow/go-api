package apiManager

import (
	"fmt"
	"net/http"
	"time"
)

func (client *APIClient) Get(url string) (*http.Response, error) {
	start := time.Now()
	rq, err := http.NewRequest("GET", client.Endpoint+url, nil)
	// logger.L.ApiRq("", rq)
	if client.Debug {
		fmt.Printf("GET %s ", client.Endpoint+url)
	}
	if err != nil {
		return nil, err
	}
	resp, err := client.do(rq)
	end := time.Now()
	if client.Debug {
		fmt.Printf("-> Done in %.2fs\n", end.Sub(start).Seconds())
	}
	return resp, err
}

// RawGet performs an authenticated GET against an arbitrary absolute URL,
// reusing the client's bearer token (plus its refresh-on-401 and
// retry-on-429/5xx behavior) instead of being scoped under client.Endpoint.
// Useful for authenticated resources served from a different host than the
// API itself (e.g. a CDN that now requires the same bearer token).
func (client *APIClient) RawGet(rawURL string) (*http.Response, error) {
	start := time.Now()
	rq, err := http.NewRequest("GET", rawURL, nil)
	if client.Debug {
		fmt.Printf("GET %s ", rawURL)
	}
	if err != nil {
		return nil, err
	}
	resp, err := client.do(rq)
	end := time.Now()
	if client.Debug {
		fmt.Printf("-> Done in %.2fs\n", end.Sub(start).Seconds())
	}
	return resp, err
}
