package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/fatih/color"
	"golang.org/x/oauth2"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

type JWTPayload struct {
	Jti            string   `json:"jti"`
	Exp            int      `json:"exp"`
	Nbf            int      `json:"nbf"`
	Iat            int      `json:"iat"`
	Iss            string   `json:"iss"`
	Aud            string   `json:"aud"`
	Sub            string   `json:"sub"`
	Typ            string   `json:"typ"`
	Azp            string   `json:"azp"`
	AuthTime       int      `json:"auth_time"`
	SessionState   string   `json:"session_state"`
	Acr            string   `json:"acr"`
	AllowedOrigins []string `json:"allowed-origins"`
	RealmAccess    struct {
		Roles []string `json:"roles"`
	} `json:"realm_access"`
	ResourceAccess struct {
		Account struct {
			Roles []string `json:"roles"`
		} `json:"account"`
	} `json:"resource_access"`
	Scope             string `json:"scope"`
	EmailVerified     bool   `json:"email_verified"`
	Name              string `json:"name"`
	PreferredUsername string `json:"preferred_username"`
	GivenName         string `json:"given_name"`
	FamilyName        string `json:"family_name"`
	Email             string `json:"email"`
}

var (
	conf *oauth2.Config
	ctx  context.Context
)

func callbackHandler(w http.ResponseWriter, r *http.Request) {

	queryParts, _ := url.ParseQuery(r.URL.RawQuery)
	// Use the authorization code that is pushed to the redirect
	// URL.
	code := queryParts["code"][0]
	log.Printf("code: %s\n", code)
	// Exchange will do the handshake to retrieve the initial access token.
	tok, err := conf.Exchange(ctx, code)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Token: %+v", tok.AccessToken)
	// The HTTP Client returned by conf.Client will refresh the token as necessary.
	//client := conf.Client(ctx, tok)
	//resp, err := client.Get("http://google.com/")
	if err != nil {
		log.Fatal(err)
	} else {
		log.Println(color.CyanString("Authentication successful"))
	}
	//defer resp.Body.Close()
	// show success page
	msg := "<p><strong>Success!</strong></p>"
	msg = msg + "<p>You are authenticated and can now return to the CLI.</p>"
	fmt.Fprintf(w, msg)

	publicKey := `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4wC2zlwk3FID4g0pDtx7LTj4ejUp6PVTbehMtgjLAYaYVshfoMqw6cEsZMRC9mUHzbH9NDkGQZkAXYT6tO5iFDVMs80PXMqiJhPi/TlLBEwTidZhRfPkGM7tt0bigGGN1MkU1yO7PQtoEqMzVD9yQjBsD3tGNX1T8YVMPe1G3XAD7MCkY7/dCBhojZXzEQC/NXIxYXTVbCwWfGgNgogsI2LeblSYDxhhb8TLOnMnHhn4JOMtkvEzlYE+NJ4X1x6UQxNaGddfTsB4Ct44xaxACPRvQi/JML89CrnWqZAsr2sGD4ID89MDCbFoufQXaCgLp8F+KYffKvBOZTlG5AtSUQIDAQAB
-----END PUBLIC KEY-----`

	isValid, err := verifyToken(tok.AccessToken, publicKey)
	if err != nil {
		log.Fatal(err)
	}

	if isValid {
		fmt.Println("The token is valid")
	} else {
		fmt.Println("The token is invalid")
	}

	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(tok.AccessToken, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(publicKey), nil
	})

	fmt.Printf("%+v\n", token.Header["kid"])

	fmt.Println(claims)

	fmt.Println()

	data, err := json.Marshal(claims)
	if err != nil {
		fmt.Println(err)
	}

	payload := JWTPayload{}

	err = json.Unmarshal(data, &payload)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Printf("%+v\n", payload)

	os.Exit(0)

}

func main() {

	ctx = context.Background()

	conf = &oauth2.Config{
		ClientID:     "go-oauth",
		ClientSecret: "052fa8fa-3d86-453a-a76e-02fdebc6ae05",
		Scopes:       []string{"openid"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "http://localhost:9000/auth/realms/golang/protocol/openid-connect/auth",
			TokenURL: "http://localhost:9000/auth/realms/golang/protocol/openid-connect/token",
		},
		// my own callback URL
		RedirectURL: "http://127.0.0.1:9999/oauth/callback",
	}
	// add transport for self-signed certificate to context
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	sslcli := &http.Client{Transport: tr}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, sslcli)
	// Redirect user to consent page to ask for permission
	// for the scopes specified above.
	url := conf.AuthCodeURL("state", oauth2.AccessTypeOffline)
	log.Println(color.CyanString("You will now be taken to your browser for authentication"))
	time.Sleep(1 * time.Second)
	//open.Run(url)
	openBrowser(url)
	time.Sleep(1 * time.Second)
	log.Printf("Authentication URL: %s\n", url)
	http.HandleFunc("/oauth/callback", callbackHandler)
	log.Fatal(http.ListenAndServe(":9999", nil))
}

func openBrowser(url string) {
	var err error

	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		err = fmt.Errorf("unsupported platform")
	}
	if err != nil {
		log.Fatal(err)
	}
}

func verifyToken(token, publicKey string) (bool, error) {
	keyData := []byte(publicKey)

	key, err := jwt.ParseRSAPublicKeyFromPEM(keyData)
	if err != nil {
		return false, err
	}

	parts := strings.Split(token, ".")
	err = jwt.SigningMethodRS512.Verify(strings.Join(parts[0:2], "."), parts[2], key)
	if err != nil {
		return false, nil
	}

	return true, nil
}
