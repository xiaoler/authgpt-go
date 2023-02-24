package authgpt

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"

	"github.com/go-resty/resty/v2"
	"github.com/tidwall/gjson"
)

var _ resty.RedirectPolicy = new(AuthRedirectPolicy)

type AuthRedirectPolicy struct{}

func (ar *AuthRedirectPolicy) Apply(req *http.Request, via []*http.Request) error {
	return http.ErrUseLastResponse
}

type Auth struct {
	username     string
	password     string
	csrfToken    string
	stateUrl     string
	state        string
	state2       string
	resumeUrl    string
	redirectUrl  string
	sessionToken string
	accessToken  string
	UA           string
	Client       *resty.Client
}

func NewAuth() *Auth {
	a := &Auth{
		Client: resty.New(),
	}
	if a.UA == "" {
		a.UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36 Edg/110.0.1587.50"
	}
	return a
}

func (a *Auth) SetProxy(proxy string) {
	a.Client.SetProxy(proxy)
}

func (a *Auth) Login(email, passsword string) error {
	if email == "" || passsword == "" {
		return errors.New("no email or password")
	}
	a.username = email
	a.password = passsword

	p := []func() error{
		a.getCsrfToken,
		a.postAuth0Url,
		a.getAuth0State,
		a.getIdentifier,
		a.postEmail,
		a.postPassword,
		a.resume,
		a.getSessionToken,
		a.getAccessToken,
	}
	for i, fn := range p {
		if err := fn(); err != nil {
			fmt.Printf("step: %d, %v", i, err)
			return err
		}
	}

	return nil
}

func (a *Auth) SessionToken() string {
	return a.sessionToken
}

func (a *Auth) AccessToken() string {
	return a.accessToken
}

func (a *Auth) Cookies() []*http.Cookie {
	return a.Client.Cookies
}

// step 0
func (a *Auth) getCsrfToken() error {
	api := "https://explorer.api.openai.com/api/auth/csrf"
	headers := map[string]string{
		"Host":            "explorer.api.openai.com",
		"Accept":          "*/*",
		"Connection":      "keep-alive",
		"User-Agent":      a.UA,
		"Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
		"Referer":         "https://explorer.api.openai.com/auth/login",
		"Accept-Encoding": "gzip, deflate, br",
	}

	resp, err := a.Client.R().SetHeaders(headers).Get(api)
	if err != nil {
		return err
	}
	a.csrfToken = gjson.Get(string(resp.Body()), "csrfToken").Str

	return nil
}

// step 1
func (a *Auth) postAuth0Url() error {
	if a.csrfToken == "" {
		return errors.New("no csrf token")
	}
	api := "https://explorer.api.openai.com/api/auth/signin/auth0?prompt=login"
	payload := fmt.Sprintf("callbackUrl=%%2F&csrfToken=%s&json=true", a.csrfToken)
	headers := map[string]string{
		"Host":            "explorer.api.openai.com",
		"User-Agent":      a.UA,
		"Content-Type":    "application/x-www-form-urlencoded",
		"Accept":          "*/*",
		"Sec-Gpc":         "1",
		"Accept-Language": "en-US,en;q=0.8",
		"Origin":          "https://explorer.api.openai.com",
		"Sec-Fetch-Site":  "same-origin",
		"Sec-Fetch-Mode":  "cors",
		"Sec-Fetch-Dest":  "empty",
		"Referer":         "https://explorer.api.openai.com/auth/login",
		"Accept-Encoding": "gzip, deflate",
	}

	resp, err := a.Client.R().SetHeaders(headers).SetBody(payload).Post(api)
	if err != nil {
		return err
	}
	if resp.StatusCode() != 200 {
		return errors.New("error response")
	}

	a.stateUrl = gjson.Get(string(resp.Body()), "url").Str
	return nil
}

// step 2
func (a *Auth) getAuth0State() error {
	if a.stateUrl == "" {
		return errors.New("no state url")
	}
	headers := map[string]string{
		"Host":            "auth0.openai.com",
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Connection":      "keep-alive",
		"User-Agent":      a.UA,
		"Accept-Language": "en-US,en;q=0.9",
		"Referer":         "https://explorer.api.openai.com/",
	}
	resp, err := a.Client.R().SetHeaders(headers).Get(a.stateUrl)
	if err != nil {
		return err
	}
	if resp.StatusCode() != 200 && resp.StatusCode() != 302 {
		return errors.New("error response")
	}
	re := regexp.MustCompile(`state=(.*?)"`)
	state := re.FindSubmatch(resp.Body())
	if len(state) == 2 {
		a.state = string(state[1])
	} else {
		return errors.New("parse state error")
	}
	return nil
}

// step 3
func (a *Auth) getIdentifier() error {
	if a.state == "" {
		return errors.New("no state")
	}
	api := fmt.Sprintf("https://auth0.openai.com/u/login/identifier?state=%s", a.state)
	headers := map[string]string{
		"Host":            "auth0.openai.com",
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Connection":      "keep-alive",
		"User-Agent":      a.UA,
		"Accept-Language": "en-US,en;q=0.9",
		"Referer":         "https://explorer.api.openai.com/",
	}

	resp, err := a.Client.R().SetHeaders(headers).Get(api)
	if err != nil {
		return err
	}
	if resp.StatusCode() != 200 {
		return errors.New("error response")
	}

	return nil
}

// step 4
func (a *Auth) postEmail() error {
	if a.state == "" || a.username == "" {
		return errors.New("no state or email")
	}
	api := fmt.Sprintf("https://auth0.openai.com/u/login/identifier?state=%s", a.state)
	payload := url.Values{}
	payload.Set("state", a.state)
	payload.Set("username", a.username)
	payload.Set("js-available", "false")
	payload.Set("webauthn-available", "true")
	payload.Set("is-brave", "false")
	payload.Set("webauthn-platform-available", "true")
	payload.Set("action", "default")

	headers := map[string]string{
		"Host":            "auth0.openai.com",
		"Origin":          "https://auth0.openai.com",
		"Connection":      "keep-alive",
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"User-Agent":      a.UA,
		"Referer":         api,
		"Accept-Language": "en-US,en;q=0.9",
		"Content-Type":    "application/x-www-form-urlencoded",
	}

	resp, err := a.Client.R().SetHeaders(headers).SetBody(payload.Encode()).Post(api)
	if err != nil {
		return err
	}
	if resp.StatusCode() != 200 && resp.StatusCode() != 302 {
		return errors.New("error response")
	}
	return nil
}

// step 5
func (a *Auth) postPassword() error {
	if a.state == "" || a.username == "" || a.password == "" {
		return errors.New("no state or email or password")
	}
	api := fmt.Sprintf("https://auth0.openai.com/u/login/password?state=%s", a.state)
	payload := url.Values{}
	payload.Set("state", a.state)
	payload.Set("username", a.username)
	payload.Set("password", a.password)
	payload.Set("action", "default")
	headers := map[string]string{
		"Host":            "auth0.openai.com",
		"Origin":          "https://auth0.openai.com",
		"Connection":      "keep-alive",
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"User-Agent":      a.UA,
		"Referer":         api,
		"Accept-Language": "en-US,en;q=0.9",
		"Content-Type":    "application/x-www-form-urlencoded",
	}
	a.Client.SetRedirectPolicy(&AuthRedirectPolicy{})
	resp, err := a.Client.R().SetHeaders(headers).SetBody(payload.Encode()).Post(api)
	if err != nil {
		return err
	}
	if resp.StatusCode() != 200 && resp.StatusCode() != 302 {
		return errors.New("error response")
	}
	re := regexp.MustCompile(`state=(.*?)"`)
	state := re.FindSubmatch(resp.Body())
	if len(state) == 2 {
		a.state2 = string(state[1])
	} else {
		return errors.New("parse state error")
	}

	return nil
}

// step 6
func (a *Auth) resume() error {
	if a.state == "" || a.state2 == "" {
		return errors.New("no state")
	}
	a.resumeUrl = fmt.Sprintf("https://auth0.openai.com/authorize/resume?state=%s", a.state2)
	headers := map[string]string{
		"Host":            "auth0.openai.com",
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Connection":      "keep-alive",
		"User-Agent":      a.UA,
		"Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
		"Referer":         fmt.Sprintf("https://auth0.openai.com/u/login/password?state=%s", a.state),
	}
	a.Client.SetRedirectPolicy(&AuthRedirectPolicy{})
	resp, err := a.Client.R().SetHeaders(headers).Get(a.resumeUrl)
	if err != nil {
		return err
	}
	if resp.StatusCode() != 302 {
		return errors.New("error response")
	}
	a.redirectUrl = resp.Header().Get("Location")
	if a.redirectUrl == "" {
		return errors.New("no redirect url")
	}

	return nil
}

// step 7
func (a *Auth) getSessionToken() error {
	if a.resumeUrl == "" || a.redirectUrl == "" {
		return errors.New("no resume url or redirect url")
	}
	headers := map[string]string{
		"Host":            "explorer.api.openai.com",
		"Accept":          "application/json",
		"Connection":      "keep-alive",
		"User-Agent":      a.UA,
		"Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
		"Referer":         a.resumeUrl,
	}
	a.Client.SetRedirectPolicy(&AuthRedirectPolicy{})
	resp, err := a.Client.R().SetHeaders(headers).Get(a.redirectUrl)
	if err != nil {
		return err
	}
	if resp.StatusCode() != 302 {
		return errors.New("error response")
	}
	for _, c := range resp.Cookies() {
		if c.Name == "__Secure-next-auth.session-token" {
			a.sessionToken = c.Value
		}
	}
	if a.sessionToken == "" {
		return errors.New("no session token")
	}
	return nil
}

// step 8
func (a *Auth) getAccessToken() error {
	if a.sessionToken == "" {
		return errors.New("no session token")
	}
	api := "https://explorer.api.openai.com/api/auth/session"
	resp, err := a.Client.R().Get(api)
	if err != nil {
		return err
	}
	if resp.StatusCode() != 200 {
		return errors.New("error response")
	}
	a.accessToken = gjson.Get(string(resp.Body()), "accessToken").Str

	return nil
}

func (a *Auth) GetModels() (string, error) {
	if a.accessToken == "" {
		return "", errors.New("no access token")
	}
	api := "https://chat.openai.com/backend-api/models"
	headers := map[string]string{
		"Host":            "chat.openai.com",
		"Accept":          "application/json",
		"User-Agent":      a.UA,
		"Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
		"Authorization":   "Bearer " + a.accessToken,
		"Referer":         "https://chat.openai.com/chat",
	}
	resp, err := a.Client.R().SetHeaders(headers).Get(api)
	if err != nil {
		return "", err
	}
	if resp.StatusCode() != 200 {
		return "", errors.New("error response")
	}

	return gjson.Get(string(resp.Body()), "models.0.slug").Str, nil
}
