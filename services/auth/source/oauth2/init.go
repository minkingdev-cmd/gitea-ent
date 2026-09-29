// Copyright 2021 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package oauth2

import (
	"context"
	"encoding/gob"
	"fmt"
	"net/http"
	"sync"
	"uuid"

	"gitea.dev/models/auth"
	"gitea.dev/models/db"
	"gitea.dev/modules/log"
	"gitea.dev/modules/setting"

	"github.com/gorilla/sessions"
	"github.com/markbates/goth/gothic"
)

var gothRWMutex = sync.RWMutex{}

// ProviderHeaderKey is the HTTP header key
const ProviderHeaderKey = "gitea-oauth2-provider"

// Init initializes the oauth source
func Init(ctx context.Context) error {
	// Lock our mutex
	gothRWMutex.Lock()

	gob.Register(&sessions.Session{}) // TODO: CHI-SESSION-GOB-REGISTER. FIXME: it seems to be an abuse, why the Session struct itself is stored in session store again?

	gothic.Store = &SessionsStore{
		maxLength: int64(setting.OAuth2.MaxTokenLength),
	}

	gothic.SetState = func(req *http.Request) string {
		return uuid.New().String()
	}

	gothic.GetProviderName = func(req *http.Request) (string, error) {
		return req.Header.Get(ProviderHeaderKey), nil
	}

	// Unlock our mutex
	gothRWMutex.Unlock()

	return initOAuth2Sources(ctx)
}

// ResetOAuth2 clears existing OAuth2 providers and loads them from DB
func ResetOAuth2(ctx context.Context) error {
	ClearProviders()
	return initOAuth2Sources(ctx)
}

// initOAuth2Sources is used to load and register all active OAuth2 providers
func initOAuth2Sources(ctx context.Context) error {
	authSources, err := db.Find[auth.Source](ctx, auth.FindSourcesOptions{
		LoginType: auth.OAuth2,
	})
	if err != nil {
		return err
	}
	if setting.EnterpriseWeCom.Enabled {
		if err := validateEnterpriseWeComSource(authSources); err != nil {
			if setting.EnterpriseWeComLoginOnly() {
				return err
			}
			log.Warn("Enterprise WeCom login source is not ready: %v", err)
		}
	}
	for _, source := range authSources {
		if !source.IsActive {
			continue
		}
		if IsWeComSource(source) && (!setting.EnterpriseWeCom.Enabled || !IsConfiguredWeComSource(source)) {
			continue
		}
		oauth2Source, ok := source.Cfg.(*Source)
		if !ok {
			continue
		}
		err := oauth2Source.RegisterSource()
		if err != nil {
			if setting.EnterpriseWeComLoginOnly() && IsConfiguredWeComSource(source) {
				return fmt.Errorf("initialize Enterprise WeCom login source %q: %w", source.Name, err)
			}
			log.Error("Unable to register source: %s due to Error: %v.", source.Name, err)
		}
	}
	return nil
}

func validateEnterpriseWeComSource(authSources []*auth.Source) error {
	name := setting.EnterpriseWeCom.LoginSourceName
	for _, source := range authSources {
		if source.Name != name {
			continue
		}
		if !source.IsActive {
			return fmt.Errorf("Enterprise WeCom login source %q is inactive", name)
		}
		if !IsWeComSource(source) {
			return fmt.Errorf("Enterprise WeCom login source %q is not a WeCom OAuth2 source", name)
		}
		return nil
	}
	return fmt.Errorf("Enterprise WeCom login source %q does not exist", name)
}
