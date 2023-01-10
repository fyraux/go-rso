package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	tls "github.com/refraction-networking/utls"
)

type UriTokens struct {
	AccessToken string `json:"access_token"`
	IdToken     string `json:"id_token"`
	ExpiresIn   int    `json:"expires_in"`
}

type ClientPlatform struct {
	Type    string `json:"platformType"`
	OS      string `json:"platformOS"`
	Version string `json:"platformOSVersion"`
	Chipset string `json:"platformChipset"`
}

type ClientVersion struct {
	ManifestId        string `json:"manifestId"`
	Branch            string `json:"branch"`
	Version           string `json:"version"`
	BuildVersion      string `json:"buildVersion"`
	EngineVersion     string `json:"engineVersion"`
	RiotClientVersion string `json:"riotClientVersion"`
	BuildDate         string `json:"buildDate"`
}

type Entitlements struct {
	Entitlements []string `json:"entitlements"`
	Hash         string   `json:"at_hash"`
	Subject      string   `json:"sub"`
	Issuer       string   `json:"iss"`
	IssuedAt     int      `json:"iat"`
	JTI          string   `json:"jti"`
}

type HandshakeRequestBody struct {
	ClientId     string `json:"client_id"`
	Nonce        int    `json:"nonce"`
	RedirectUri  string `json:"redirect_uri"`
	ResponseType string `json:"response_type"`
	Scope        string `json:"scope"`
}

type HandshakeResponseBody struct {
	Type    string `json:"type"`
	Country string `json:"country"`
}

type LoginRequestBody struct {
	Type     string `json:"type"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponseBody struct {
	Type     string `json:"type"`
	Response struct {
		Mode       string `json:"mode"`
		Parameters struct {
			Uri string `json:"uri"`
		} `json:"parameters"`
	} `json:"response"`
	Country string `json:"country"`
}

type EntitlementsResponseBody struct {
	Token string `json:"entitlements_token"`
}

type ClientVersionResponseBody struct {
	Status int           `json:"status"`
	Data   ClientVersion `json:"data"`
}

type NameServiceResponseBody struct {
	DisplayName string `json:"DisplayName"`
	Subject     string `json:"Subject"`
	GameName    string `json:"GameName"`
	TagLine     string `json:"TagLine"`
}

var (
	defaultHeaders = http.Header{
		"Content-Type": {"application/json"},
		"Cookie":       {""},
		"User-Agent":   {"RiotClient/43.0.1.4195386.4190634 rso-auth (Windows; 10;;Professional, x64)"},
	}
	authHeaders = http.Header{}
	tlsConfig   = tls.Config{
		CipherSuites: []uint16{tls.TLS_AES_128_GCM_SHA256},
		MinVersion:   tls.VersionTLS13,
	}
	clientPlatoform = ClientPlatform{
		Type:    "PC",
		OS:      "Windows",
		Version: "10.0.19043.1.256.64bit",
		Chipset: "Unknown",
	}
)

// tokensFromUri parses the given uri for the access token, id token, and expires in time.
func tokensFromUri(uri string) (*UriTokens, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}

	q, err := url.ParseQuery(u.Fragment)
	if err != nil {
		return nil, err
	}

	accessToken := q.Get("access_token")
	idToken := q.Get("id_token")

	expiresIn, err := strconv.Atoi(q.Get("expires_in"))
	if err != nil {
		return nil, err
	}

	return &UriTokens{
		AccessToken: accessToken,
		IdToken:     idToken,
		ExpiresIn:   expiresIn,
	}, nil
}

// parseCookies gets the cookie containing the provided substring
func parseCookies(cookies []string, subs string) (string, error) {
	for _, cookie := range cookies {
		if strings.Contains(cookie, subs) {
			return cookie, nil
		}
	}
	return "", fmt.Errorf("Could not find %s", subs)
}

// parseSubject gets the puuid from the entitlements token
func parseSubject(entitlement string) (string, error) {
	token := strings.Split(entitlement, ".")[1]
	decoded, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return "", err
	}

	body := new(Entitlements)
	if err := json.Unmarshal(decoded, &body); err != nil {
		return "", err
	}

	return body.Subject, nil
}

// dialTLS is a dialer that connects to the given host via an encrypted TLS channel.
// This allows us to alter the TLS configuration before the TLS handshake.
func dialTLS(network, addr string) (net.Conn, error) {
	netConn, err := net.Dial(network, addr)
	if err != nil {
		return nil, err
	}

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	// Clone the config and set the ServerName to the host we're connecting to.
	config := tlsConfig.Clone()
	config.ServerName = host

	tlsConn := tls.UClient(netConn, config, tls.HelloGolang)
	if err = tlsConn.Handshake(); err != nil {
		return nil, err
	}

	return tlsConn, nil
}

// newHttpClient creates a new HTTP client with our custom dialer.
func newHttpClient() *http.Client {
	return &http.Client{Transport: &http.Transport{DialTLS: dialTLS}}
}

// newHttpRequest is a short-hand function for creating a new HTTP request.
// A couple key benefits to this:
// (1) We can be lazy pass in a data object and have it encoded.
// (2) We do not have to manually set the referer for every request.
func newHttpRequest(method, url string, data interface{}) (*http.Request, error) {
	body, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(method, url, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	// Clone headers and set the referer to the host.
	req.Header = authHeaders.Clone()
	req.Header.Set("Referer", req.URL.Host)

	return req, nil
}

// doHttpRequest is a short hand for performing an HTTP request.
func doHttpRequest(method, url string, data any) (*http.Response, error) {
	req, err := newHttpRequest(method, url, data)
	if err != nil {
		return nil, err
	}

	res, err := newHttpClient().Do(req)
	if err != nil {
		return nil, err
	}

	return res, nil
}

// clientPlatform gets the base64 encoded client platform.
func clientPlatform() (string, error) {
	body, err := json.Marshal(clientPlatoform)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(body), nil
}

// clientVersion gets latest Valorant client version.
func clientVersion() (string, error) {
	res, err := http.Get("https://valorant-api.com/v1/version")
	if err != nil {
		return "", err
	}

	defer res.Body.Close()
	body := new(ClientVersionResponseBody)
	if err = json.NewDecoder(res.Body).Decode(&body); err != nil {
		return "", err
	}

	return body.Data.Version, nil
}

// handshake with Riot Games.
func handshake() (string, error) {
	res, err := doHttpRequest(http.MethodPost, "https://auth.riotgames.com/api/v1/authorization", HandshakeRequestBody{
		ClientId:     "play-valorant-web-prod",
		Nonce:        1,
		RedirectUri:  "https://playvalorant.com/opt_in",
		ResponseType: "token id_token",
		Scope:        "openid account",
	})
	if err != nil {
		return "", err
	}

	defer res.Body.Close()
	body := new(HandshakeResponseBody)
	if err = json.NewDecoder(res.Body).Decode(&body); err != nil {
		return "", err
	}

	cookie, err := parseCookies(res.Header["Set-Cookie"], "asid")
	if err != nil {
		return "", err
	}

	return cookie, nil
}

// login logs in to Riot Games with the given username and password.
func login(username, password string) (*UriTokens, string, error) {
	res, err := doHttpRequest(http.MethodPut, "https://auth.riotgames.com/api/v1/authorization", LoginRequestBody{
		Type:     "auth",
		Username: username,
		Password: password,
	})
	if err != nil {
		return nil, "", err
	}

	defer res.Body.Close()
	body := new(LoginResponseBody)
	if err = json.NewDecoder(res.Body).Decode(&body); err != nil {
		return nil, "", err
	}

	tokens, err := tokensFromUri(body.Response.Parameters.Uri)
	if err != nil {
		return nil, "", err
	}

	cookie, err := parseCookies(res.Header["Set-Cookie"], "ssid")
	if err != nil {
		return nil, "", err
	}

	return tokens, cookie, nil
}

// entitlements gets the entitlements token after login.
func entitlements() (string, error) {
	res, err := doHttpRequest(http.MethodPost, "https://entitlements.auth.riotgames.com/api/token/v1", nil)
	if err != nil {
		return "", err
	}

	defer res.Body.Close()
	body := new(EntitlementsResponseBody)
	if err = json.NewDecoder(res.Body).Decode(&body); err != nil {
		return "", err
	}

	return body.Token, nil
}

// nameService gets the name and tag from a subject id and region.
func nameService(region string, subject string) (*NameServiceResponseBody, error) {
	res, err := doHttpRequest(http.MethodPut, fmt.Sprintf("https://pd.%s.a.pvp.net/name-service/v2/players", region), []string{subject})
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()
	var body []*NameServiceResponseBody
	if err = json.NewDecoder(res.Body).Decode(&body); err != nil {
		return nil, err
	}

	return body[0], nil
}

// authenticate does the full authentication process with Riot Games.
func authenticate(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")
	region := r.FormValue("region")

	if username == "" || password == "" || region == "" {
		http.Error(w, "username, password, and region are required", http.StatusBadRequest)
		return
	}

	platform, err := clientPlatform()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	authHeaders = defaultHeaders.Clone()
	authHeaders.Set("X-Riot-ClientPlatform", platform)

	cookie, err := handshake()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// ASID cookie is required for the login request.
	authHeaders.Set("Cookie", cookie)

	tokens, cookie, err := login(username, password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	authHeaders.Set("Cookie", cookie)
	authHeaders.Set("Authorization", "Bearer "+tokens.AccessToken)

	token, err := entitlements()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	version, err := clientVersion()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	authHeaders.Set("X-Riot-Entitlements-JWT", token)
	authHeaders.Set("X-Riot-ClientVersion", version)

	subject, err := parseSubject(token)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Test that authentication was successful and that we can make requests.
	name, err := nameService(region, subject)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(name)
}

func main() {
	// We do this with gorilla/mux to quickly test the authentication process.
	router := mux.NewRouter()

	// Use cURL, Postman, etc to send region, username, and password.
	// Then view the response (you should get your subject back and more).
	router.HandleFunc("/rso", authenticate).Methods(http.MethodPost)

	server := &http.Server{
		Handler: router,
		Addr:    "127.0.0.1:8000",
	}

	err := server.ListenAndServe()
	if err != nil {
		log.Fatalln(err)
	}
}
