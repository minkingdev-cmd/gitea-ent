// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package common

import (
	stdcontext "context"
	"errors"
	"io"
	"mime"
	"net/http"

	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/json"
	"gitea.dev/modules/reqctx"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/web/types"
	"gitea.dev/services/context"
	authz_service "gitea.dev/services/enterpriseauthz"
)

type repoLifecycleRouteKey struct{}

func RepoLifecycleMutationRoute(archiveJSON bool) types.PreMiddlewareProvider {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if setting.EnterpriseAuthz.Enabled && req.Method != http.MethodGet && req.Method != http.MethodHead {
				reqctx.GetRequestDataStore(req.Context()).SetContextValue(repoLifecycleRouteKey{}, archiveJSON)
			}
			next.ServeHTTP(w, req)
		})
	}
}

func observeMarkedLifecycleDenial(base *context.Base, actor *user_model.User, repo *context.Repository, source string) {
	archiveJSON, ok := base.Value(repoLifecycleRouteKey{}).(bool)
	if !ok {
		return
	}
	input := authz_service.EvaluateInput{Actor: actor, Repo: repo.Repository, Permission: &repo.Permission, Credential: RepoCredentialCeiling(base, actor), Action: "", ConditionContext: authz.ConditionContext{Source: source}}
	authz_service.ObservePreparedGuardDenials(base, input, func(ctx stdcontext.Context, input authz_service.EvaluateInput) ([]authz_service.EvaluateInput, error) {
		actions, err := nativeLifecycleGuardActions(ctx, base, archiveJSON)
		if err != nil {
			return nil, err
		}
		inputs := make([]authz_service.EvaluateInput, 0, len(actions))
		for _, action := range actions {
			input.Action = action
			inputs = append(inputs, input)
		}
		return inputs, nil
	})
}

func nativeLifecycleGuardActions(ctx stdcontext.Context, base *context.Base, archiveJSON bool) ([]authz.Action, error) {
	if !archiveJSON {
		action, err := nativeGuardFormValue(ctx, base, "action")
		if err != nil {
			return nil, err
		}
		switch action {
		case "archive", "unarchive":
			return []authz.Action{authz.Archive}, nil
		case "transfer":
			return []authz.Action{authz.Transfer}, nil
		case "delete":
			return []authz.Action{authz.Delete}, nil
		default:
			return nil, nil
		}
	}
	mediaType, _, err := mime.ParseMediaType(base.Req.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return nil, errors.New("target_form_unresolved")
	}
	reset, err := nativeGuardBodyDeadline(ctx, base)
	if err != nil {
		return nil, err
	}
	defer reset()
	data, err := io.ReadAll(http.MaxBytesReader(nil, base.Req.Body, 64<<10))
	if err != nil {
		return nil, errors.New("target_form_unresolved")
	}
	var options struct {
		Archived   *bool `json:"archived"`
		HasActions *bool `json:"has_actions"`
	}
	if json.Unmarshal(data, &options) != nil {
		return nil, nil
	}
	var actions []authz.Action
	if options.Archived != nil {
		actions = append(actions, authz.Archive)
	}
	if options.HasActions != nil {
		actions = append(actions, authz.ManageCI)
	}
	return actions, nil
}
