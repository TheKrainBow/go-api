package apiManager

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type AuthType string

const (
	// Regular OAuth flow with client secret and id
	AuthTypeClientCredentials AuthType = "client_credentials"
	// Password type authentification (need client id, secret, username and password)
	AuthTypePassword AuthType = "password"
	// Basic type authentification (Only need username and password)
	AuthTypeBasic AuthType = "basic"
)

type APIClientInput struct {
	AuthType     AuthType
	TokenURL     string
	Endpoint     string
	TestPath     string
	ClientID     string
	ClientSecret string
	Username     string
	Password     string
	Scope        string
	Debug        bool
}

type APIClient struct {
	TokenURL     string
	Endpoint     string
	TestPath     string
	ClientID     string
	ClientSecret string
	Username     string
	Password     string
	Scope        string

	authType AuthType
	client   *http.Client

	Debug bool
}

var clients map[string]*APIClient

type authTransport struct {
	underlyingTransport http.RoundTripper
	token               string
	refreshFunc         func() (string, error) // Function to refresh the token
}

type debugTransport struct {
	underlying http.RoundTripper
	enabled    bool
}

func (dt *debugTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if dt.enabled {
		// Log Request
		fmt.Printf("➡️ REQUEST: %s %s\n", req.Method, req.URL)
		for name, values := range req.Header {
			for _, value := range values {
				fmt.Printf("  %s: %s\n", name, value)
			}
		}
		if req.Body != nil {
			bodyBytes, _ := io.ReadAll(req.Body)
			fmt.Printf("   Body: %s\n", string(bodyBytes))
			// Need to restore body because it's read-once
			req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}
	}

	resp, err := dt.underlying.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	if dt.enabled {
		// Log Response
		fmt.Printf("⬅️ RESPONSE: %d %s\n", resp.StatusCode, resp.Status)
		for name, values := range resp.Header {
			for _, value := range values {
				fmt.Printf("  %s: %s\n", name, value)
			}
		}
		if resp.Body != nil {
			bodyBytes, _ := io.ReadAll(resp.Body)
			fmt.Printf("  Body: %s\n", string(bodyBytes))
			resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}
	}

	return resp, nil
}

func init() {
	clients = make(map[string]*APIClient)
}

func (client *APIClient) TestConnection() error {
	resp, err := client.Get(client.TestPath)
	if err != nil {
		log.Fatalf("Request failed: %v", err)
		return err
	}
	defer resp.Body.Close()
	return nil
}

func (t *authTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Add the Authorization header
	req.Header.Set("Authorization", "Bearer "+t.token)

	// Make the request
	resp, err := t.underlyingTransport.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	// If the token is expired, try to refresh and retry the request
	if resp.StatusCode == http.StatusUnauthorized {
		newToken, err := t.refreshFunc()
		if err != nil {
			return nil, fmt.Errorf("failed to refresh token: %w", err)
		}

		// Update the token and retry the request
		t.token = newToken
		req.Header.Set("Authorization", "Bearer "+t.token)
		resp.Body.Close() // Close the previous response body
		return t.underlyingTransport.RoundTrip(req)
	}

	return resp, nil
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

type TokenErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func basicAuthHeader(clientID, clientSecret string) string {
	creds := clientID + ":" + clientSecret
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(creds))
}

func requestToken(config APIClientInput) (*TokenResponse, error) {
	data := url.Values{}
	data.Set("grant_type", string(config.AuthType))
	if config.Scope != "" {
		data.Set("scope", config.Scope)
	}
	if config.AuthType == AuthTypePassword {
		data.Set("username", config.Username)
		data.Set("password", config.Password)
	}

	req, err := http.NewRequest("POST", config.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if config.AuthType != AuthTypeBasic {
		req.Header.Set("Authorization", basicAuthHeader(config.ClientID, config.ClientSecret))
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, err
	}

	var tokenErrorResp TokenErrorResponse
	if err := json.Unmarshal(body, &tokenErrorResp); err != nil {
		return nil, err
	}

	if tokenErrorResp.ErrorDescription != "" {
		return nil, fmt.Errorf("%s", tokenErrorResp.ErrorDescription)
	}

	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("no access token received")
	}

	return &tokenResp, nil
}

func NewBasicAPIClient(name string, username string, password string, endpoint string, testPath string, unsecure bool) (newClient *APIClient, err error) {
	newClient = &APIClient{}
	newClient.client = &http.Client{}
	if unsecure {
		newClient.client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}
	newClient.authType = AuthTypeBasic
	newClient.Username = username
	newClient.Password = password
	newClient.Endpoint = endpoint
	newClient.TestPath = testPath
	newClient.Debug = false
	clients[name] = newClient
	return newClient, nil
}

func NewAPIClient(name string, config APIClientInput) (newClient *APIClient, err error) {
	if config.AuthType == AuthTypeBasic {
		return NewBasicAPIClient(name, config.Username, config.Password, config.Endpoint, config.TestPath, true)
	}
	// Request the initial token
	tokenResp, err := requestToken(config)
	if err != nil {
		return nil, err
	}
	newClient = &APIClient{}
	newClient.client = &http.Client{
		Transport: &authTransport{
			underlyingTransport: &debugTransport{
				underlying: http.DefaultTransport,
				enabled:    config.Debug,
			},
			token: tokenResp.AccessToken,
			refreshFunc: func() (string, error) {
				// Refresh the token
				newTokenResp, err := requestToken(config)
				if err != nil {
					return "", err
				}
				return newTokenResp.AccessToken, nil
			},
		},
	}
	newClient.authType = config.AuthType
	newClient.ClientID = config.ClientID
	newClient.ClientSecret = config.ClientSecret
	newClient.Username = config.Username
	newClient.Password = config.Password
	newClient.Scope = config.Scope
	newClient.Endpoint = config.Endpoint
	newClient.TokenURL = config.TokenURL
	newClient.Debug = config.Debug
	clients[name] = newClient
	return newClient, nil
}

func GetClient(name string) *APIClient {
	return clients[name]
}

func (ft *APIClient) do(rq *http.Request) (*http.Response, error) {
	rq.Header.Set("Content-Type", "application/json")
	if ft.authType == AuthTypeBasic {
		rq.SetBasicAuth(ft.Username, ft.Password)
	}
	var resp *http.Response
	var err error
	for i := range 5 {
		resp, err = ft.client.Do(rq)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode == http.StatusTooManyRequests {
			delay, err := strconv.ParseInt(resp.Header.Get("Retry-After"), 10, 64)
			if err != nil {
				time.Sleep(2 * time.Second)
				continue
			}
			time.Sleep(time.Duration(delay) * time.Second)
			continue
		}

		if resp.StatusCode == http.StatusBadGateway || resp.StatusCode == http.StatusServiceUnavailable {
			if ft.Debug {
				log.Printf("Retry %d with status %s\n", i, resp.Status)
			}
			time.Sleep(2 * time.Second)
			continue
		} else if ft.Debug {
			log.Printf("Success in %d tries with status %s\n", i, resp.Status)
		}
	}
	return nil, fmt.Errorf("retried 5 times and still failed")
}
