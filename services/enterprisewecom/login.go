// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterprisewecom

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	audit_model "gitea.dev/models/audit"
	auth_model "gitea.dev/models/auth"
	wecom_model "gitea.dev/models/enterprisewecom"
	user_model "gitea.dev/models/user"
	"gitea.dev/modules/log"
	"gitea.dev/modules/optional"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/timeutil"
	"gitea.dev/services/audit"

	"github.com/markbates/goth"
)

type OAuthIdentity struct {
	CorpID  string
	AgentID string
	UserID  string
	Name    string
	Email   string
}

var refreshAdminAuthorityForLogin = func(ctx context.Context, identity *OAuthIdentity) error {
	_, err := RefreshAdminAuthoritySnapshot(ctx, NewClientFromSettings(), AdminAuthorityRefreshOptions{
		CorpID:  identity.CorpID,
		AgentID: identity.AgentID,
		Trigger: "login",
		RunID:   fmt.Sprintf("login-%d", timeutil.TimeStampNow()),
	})
	return err
}

func AuthenticateOAuthLogin(ctx context.Context, authSource *auth_model.Source, existingUser, currentUser *user_model.User, gothUser goth.User) (*user_model.User, error) {
	if !setting.EnterpriseWeCom.Enabled {
		return nil, ErrWeComDisabled
	}
	identity, err := OAuthIdentityFromGoth(gothUser)
	if err != nil {
		recordLoginDeny(ctx, nil, identity, authSource, "invalid_identity")
		return nil, err
	}
	if err := validateIdentityBoundary(identity); err != nil {
		recordLoginDeny(ctx, nil, identity, authSource, "boundary_mismatch")
		return nil, err
	}

	bound, has, err := wecom_model.GetIdentityByCorpAndUserID(ctx, identity.CorpID, identity.UserID)
	if err != nil {
		return nil, err
	}
	if has {
		if bound.Status != wecom_model.IdentityStatusActive && bound.Status != wecom_model.IdentityStatusOutOfScope {
			recordLoginDeny(ctx, nil, identity, authSource, string(bound.Status))
			return nil, fmt.Errorf("%w: identity status %s", ErrWeComDenied, bound.Status)
		}
		u, err := user_model.GetUserByID(ctx, bound.UserID)
		if err != nil {
			return nil, err
		}
		if !u.IsIndividual() {
			recordLoginDeny(ctx, nil, identity, authSource, "bound_user_not_individual")
			return nil, fmt.Errorf("%w: bound user is not an individual", ErrWeComDenied)
		}
		if err := upsertIdentity(ctx, authSource, u, identity); err != nil {
			return nil, err
		}
		if err := refreshAndPromoteProtectedAdminsAfterLogin(ctx, identity); err != nil {
			return nil, err
		}
		recordLoginSuccess(ctx, u, identity, authSource)
		return u, nil
	}

	u := currentUser
	if u == nil {
		u = existingUser
	}
	if u == nil {
		if !setting.EnterpriseWeCom.AutoCreateUser {
			recordLoginDeny(ctx, nil, identity, authSource, "auto_create_disabled")
			return nil, fmt.Errorf("%w: auto create user is disabled", ErrWeComDenied)
		}
		u, err = createUserForIdentity(ctx, authSource, identity)
		if err != nil {
			return nil, err
		}
		audit.RecordAs(ctx, user_model.NewAuthSourceUser(), audit_model.UserCreate, u)
	}
	if !u.IsIndividual() {
		recordLoginDeny(ctx, u, identity, authSource, "target_user_not_individual")
		return nil, fmt.Errorf("%w: target user is not an individual", ErrWeComDenied)
	}
	if err := upsertIdentity(ctx, authSource, u, identity); err != nil {
		recordLoginDeny(ctx, u, identity, authSource, "identity_already_bound")
		return nil, err
	}
	if err := refreshAndPromoteProtectedAdminsAfterLogin(ctx, identity); err != nil {
		return nil, err
	}
	audit.RecordAs(ctx, user_model.NewAuthSourceUser(), audit_model.EnterpriseWeComIdentityBind, u,
		"external_id", wecom_model.MakeExternalID(identity.CorpID, identity.UserID),
		"login_source_id", authSource.ID,
	)
	recordLoginSuccess(ctx, u, identity, authSource)
	return u, nil
}

func refreshAndPromoteProtectedAdminsAfterLogin(ctx context.Context, identity *OAuthIdentity) error {
	if err := refreshAdminAuthorityForLogin(ctx, identity); err != nil && !errors.Is(err, ErrWeComAuthorityUnsupported) {
		log.Warn("Unable to refresh Enterprise WeCom administrator authority during login: %v", err)
	}
	_, err := PromoteProtectedAdmins(ctx, ProtectedAdminResolveOptions{CorpID: identity.CorpID, AgentID: identity.AgentID})
	return err
}

func OAuthIdentityFromGoth(gothUser goth.User) (*OAuthIdentity, error) {
	identity := &OAuthIdentity{
		CorpID:  rawString(gothUser.RawData, "wecom_corp_id"),
		AgentID: rawString(gothUser.RawData, "wecom_agent_id"),
		UserID:  firstNonEmpty(rawString(gothUser.RawData, "wecom_userid"), gothUser.UserID),
		Name:    gothUser.Name,
		Email:   gothUser.Email,
	}
	if identity.UserID == "" {
		return identity, fmt.Errorf("%w: missing userid", ErrWeComDenied)
	}
	return identity, nil
}

func validateIdentityBoundary(identity *OAuthIdentity) error {
	if identity.CorpID != "" && identity.CorpID != setting.EnterpriseWeCom.CorpID {
		return fmt.Errorf("%w: corp mismatch", ErrWeComDenied)
	}
	if identity.AgentID != "" && identity.AgentID != setting.EnterpriseWeCom.AgentID {
		return fmt.Errorf("%w: agent mismatch", ErrWeComDenied)
	}
	identity.CorpID = setting.EnterpriseWeCom.CorpID
	identity.AgentID = setting.EnterpriseWeCom.AgentID
	return nil
}

func upsertIdentity(ctx context.Context, authSource *auth_model.Source, u *user_model.User, identity *OAuthIdentity) error {
	now := timeutil.TimeStamp(time.Now().Unix())
	_, created, err := wecom_model.BindIdentityToUser(ctx, wecom_model.BindIdentityOptions{
		UserID:        u.ID,
		CorpID:        identity.CorpID,
		WeComUserID:   identity.UserID,
		LoginSourceID: authSource.ID,
		Status:        wecom_model.IdentityStatusActive,
		Name:          identity.Name,
		Email:         identity.Email,
		LastLoginUnix: now,
	})
	if err != nil {
		return err
	}
	if !created {
		audit.RecordAs(ctx, user_model.NewAuthSourceUser(), audit_model.EnterpriseWeComIdentityUpdate, u,
			"external_id", wecom_model.MakeExternalID(identity.CorpID, identity.UserID),
			"login_source_id", authSource.ID,
		)
	}
	return nil
}

func createUserForIdentity(ctx context.Context, authSource *auth_model.Source, identity *OAuthIdentity) (*user_model.User, error) {
	username, err := uniqueUsername(ctx, identity)
	if err != nil {
		return nil, err
	}
	u := &user_model.User{
		Name:        username,
		Email:       syntheticEmail(identity),
		LoginType:   auth_model.OAuth2,
		LoginSource: authSource.ID,
		LoginName:   identity.UserID,
	}
	if identity.Name != "" {
		u.FullName = identity.Name
	}
	overwriteDefault := &user_model.CreateUserOverwriteOptions{IsActive: optional.Some(true)}
	return u, user_model.CreateUser(ctx, u, &user_model.Meta{}, overwriteDefault)
}

func uniqueUsername(ctx context.Context, identity *OAuthIdentity) (string, error) {
	base := renderUsername(identity)
	base, err := user_model.NormalizeUserName(base)
	if err != nil || base == "" {
		base, err = user_model.NormalizeUserName(identity.UserID)
	}
	if err != nil || base == "" {
		base = "wecom-user"
	}
	exists, err := user_model.IsUserExist(ctx, 0, base)
	if err != nil || !exists {
		return base, err
	}

	sum := sha256.Sum256([]byte(identity.CorpID + ":" + identity.UserID))
	suffix := hex.EncodeToString(sum[:])[:8]
	candidate := base + "-wecom-" + suffix
	exists, err = user_model.IsUserExist(ctx, 0, candidate)
	if err != nil || !exists {
		return candidate, err
	}
	for i := 2; ; i++ {
		next := fmt.Sprintf("%s-%d", candidate, i)
		exists, err = user_model.IsUserExist(ctx, 0, next)
		if err != nil || !exists {
			return next, err
		}
	}
}

func renderUsername(identity *OAuthIdentity) string {
	template := firstNonEmpty(setting.EnterpriseWeCom.UsernameTemplate, "{userid}")
	replacer := strings.NewReplacer(
		"{userid}", identity.UserID,
		"{corp_id}", identity.CorpID,
	)
	return replacer.Replace(template)
}

func syntheticEmail(identity *OAuthIdentity) string {
	sum := sha256.Sum256([]byte(identity.CorpID + ":" + identity.UserID))
	return "wecom-" + hex.EncodeToString(sum[:])[:16] + "@wecom.local"
}

func recordLoginSuccess(ctx context.Context, u *user_model.User, identity *OAuthIdentity, authSource *auth_model.Source) {
	audit.RecordAs(ctx, user_model.NewAuthSourceUser(), audit_model.EnterpriseWeComLoginSuccess, u,
		"external_id", wecom_model.MakeExternalID(identity.CorpID, identity.UserID),
		"login_source_id", authSource.ID,
		"outcome", "success",
	)
}

// RecordCallbackLoginDeny records a denied WeCom callback before a member identity can be resolved.
func RecordCallbackLoginDeny(ctx context.Context, authSource *auth_model.Source, reason string) {
	recordLoginDeny(ctx, nil, nil, authSource, reason)
}

func recordLoginDeny(ctx context.Context, u *user_model.User, identity *OAuthIdentity, authSource *auth_model.Source, reason string) {
	scope := any(nil)
	if u != nil {
		scope = u
	}
	externalID := ""
	if identity != nil && identity.CorpID != "" && identity.UserID != "" {
		externalID = wecom_model.MakeExternalID(identity.CorpID, identity.UserID)
	}
	metadata := []any{
		"external_id", externalID,
		"reason", reason,
		"outcome", "deny",
	}
	if authSource != nil {
		metadata = append(metadata, "login_source_id", authSource.ID)
	}
	audit.RecordAs(ctx, user_model.NewAuthSourceUser(), audit_model.EnterpriseWeComLoginDeny, scope, metadata...)
}

func rawString(data map[string]any, key string) string {
	value, _ := data[key].(string)
	return strings.TrimSpace(value)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
