// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package oauth2

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"gitea.dev/models/auth"
	"gitea.dev/modules/json"
	"gitea.dev/modules/setting"
	wecom_service "gitea.dev/services/enterprisewecom"

	"github.com/markbates/goth"
	go_oauth2 "golang.org/x/oauth2"
)

const ProviderNameWeCom = "wecom"

func IsWeComSource(source *auth.Source) bool {
	if source == nil || source.Type != auth.OAuth2 {
		return false
	}
	oauth2Source, ok := source.Cfg.(*Source)
	return ok && oauth2Source.Provider == ProviderNameWeCom
}

func IsConfiguredWeComSource(source *auth.Source) bool {
	return IsWeComSource(source) && source.Name == setting.EnterpriseWeCom.LoginSourceName
}

type WeComProvider struct {
	BaseProvider
}

func (p *WeComProvider) CreateGothProvider(providerName, callbackURL string, source *Source) (goth.Provider, error) {
	cfg := setting.EnterpriseWeCom
	if cfg.CorpID == "" || cfg.CorpSecret == "" || cfg.AgentID == "" {
		return nil, errors.New("wecom oauth provider requires CORP_ID, AGENT_ID, and CORP_SECRET")
	}
	httpTimeout := cfg.HTTPTimeout
	if httpTimeout <= 0 {
		httpTimeout = 15 * time.Second
	}
	return newWeComGothProvider(weComGothConfig{
		Name:         providerName,
		CorpID:       cfg.CorpID,
		AgentID:      cfg.AgentID,
		CorpSecret:   cfg.CorpSecret,
		CallbackURL:  callbackURL,
		APIBaseURL:   cfg.APIBaseURL,
		OAuthBaseURL: cfg.OAuthBaseURL,
		HTTPTimeout:  httpTimeout,
	}), nil
}

type weComGothConfig struct {
	Name         string
	CorpID       string
	AgentID      string
	CorpSecret   string
	CallbackURL  string
	APIBaseURL   string
	OAuthBaseURL string
	HTTPTimeout  time.Duration
}

type weComGothProvider struct {
	name         string
	corpID       string
	agentID      string
	corpSecret   string
	callbackURL  string
	apiBaseURL   string
	oauthBaseURL string
	httpTimeout  time.Duration
}

func newWeComGothProvider(cfg weComGothConfig) *weComGothProvider {
	cfg.OAuthBaseURL = strings.TrimRight(firstNonEmpty(cfg.OAuthBaseURL, "https://open.weixin.qq.com"), "/")
	return &weComGothProvider{
		name:         cfg.Name,
		corpID:       cfg.CorpID,
		agentID:      cfg.AgentID,
		corpSecret:   cfg.CorpSecret,
		callbackURL:  cfg.CallbackURL,
		apiBaseURL:   cfg.APIBaseURL,
		oauthBaseURL: cfg.OAuthBaseURL,
		httpTimeout:  cfg.HTTPTimeout,
	}
}

func (p *weComGothProvider) Name() string {
	return p.name
}

func (p *weComGothProvider) SetName(name string) {
	p.name = name
}

func (p *weComGothProvider) Debug(bool) {}

func (p *weComGothProvider) BeginAuth(state string) (goth.Session, error) {
	values := url.Values{}
	values.Set("appid", p.corpID)
	values.Set("redirect_uri", p.callbackURL)
	values.Set("response_type", "code")
	values.Set("scope", "snsapi_base")
	values.Set("state", state)
	values.Set("agentid", p.agentID)

	return &weComSession{
		AuthURL: fmt.Sprintf("%s/connect/oauth2/authorize?%s#wechat_redirect", p.oauthBaseURL, values.Encode()),
		CorpID:  p.corpID,
		AgentID: p.agentID,
	}, nil
}

func (p *weComGothProvider) UnmarshalSession(data string) (goth.Session, error) {
	session := &weComSession{}
	err := json.NewDecoder(strings.NewReader(data)).Decode(session)
	return session, err
}

func (p *weComGothProvider) FetchUser(session goth.Session) (goth.User, error) {
	s, ok := session.(*weComSession)
	if !ok {
		return goth.User{}, errors.New("invalid wecom session")
	}
	user := goth.User{
		Provider: p.Name(),
		UserID:   s.UserID,
		Name:     s.Name,
		Email:    s.Email,
		RawData: map[string]any{
			"wecom_corp_id":  s.CorpID,
			"wecom_agent_id": s.AgentID,
			"wecom_userid":   s.UserID,
			"wecom_deviceid": s.DeviceID,
		},
	}
	if s.UserID == "" {
		return user, errors.New("wecom user information has not been resolved")
	}
	return user, nil
}

func (p *weComGothProvider) RefreshToken(string) (*go_oauth2.Token, error) {
	return nil, errors.New("wecom refresh token is not supported")
}

func (p *weComGothProvider) RefreshTokenAvailable() bool {
	return false
}

type weComSession struct {
	AuthURL  string
	CorpID   string
	AgentID  string
	UserID   string
	DeviceID string
	Name     string
	Email    string
}

func (s *weComSession) GetAuthURL() (string, error) {
	if s.AuthURL == "" {
		return "", errors.New(goth.NoAuthUrlErrorMessage)
	}
	return s.AuthURL, nil
}

func (s *weComSession) Authorize(provider goth.Provider, params goth.Params) (string, error) {
	p, ok := provider.(*weComGothProvider)
	if !ok {
		return "", errors.New("invalid wecom provider")
	}
	code := strings.TrimSpace(params.Get("code"))
	if code == "" {
		return "", fmt.Errorf("%w: missing authorization code", wecom_service.ErrWeComDenied)
	}
	ctx, cancel := context.WithTimeout(context.Background(), p.httpTimeout)
	defer cancel()
	member, err := wecom_service.NewClient(wecom_service.Config{
		CorpID:      p.corpID,
		CorpSecret:  p.corpSecret,
		AgentID:     p.agentID,
		APIBaseURL:  p.apiBaseURL,
		HTTPTimeout: p.httpTimeout,
	}).ResolveOAuthUser(ctx, code)
	if err != nil {
		return "", err
	}
	s.CorpID = member.CorpID
	s.AgentID = member.AgentID
	s.UserID = member.UserID
	s.DeviceID = member.DeviceID
	s.Name = member.Name
	s.Email = member.Email
	return member.UserID, nil
}

func (s *weComSession) Marshal() string {
	b, _ := json.Marshal(s)
	return string(b)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func init() {
	RegisterGothProvider(&WeComProvider{
		BaseProvider: BaseProvider{
			name:        ProviderNameWeCom,
			displayName: "Enterprise WeCom",
		},
	})
}

var (
	_ GothProvider  = &WeComProvider{}
	_ goth.Provider = &weComGothProvider{}
	_ goth.Session  = &weComSession{}
)
