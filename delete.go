package apiManager

import (
	"net/http"
)

func (ft *APIClient) Delete(url string) (*http.Response, error) {
	rq, err := http.NewRequest("DELETE", ft.Endpoint+url, nil)
	// logger.L.ApiRq("", rq)
	if err != nil {
		return nil, err
	}
	return ft.do(rq)
}
