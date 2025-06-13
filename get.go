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
