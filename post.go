package apiManager

import (
	"bytes"
	"encoding/json"
	"net/http"
)

func (ft *APIClient) Post(url string, data interface{}) (*http.Response, error) {
	jason, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	rq, err := http.NewRequest("POST", ft.Endpoint+url, bytes.NewReader(jason))
	// logger.L.ApiRq("", rq)
	if err != nil {
		return nil, err
	}
	return ft.do(rq)
}
