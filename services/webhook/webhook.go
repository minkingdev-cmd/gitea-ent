// Copyright 2019 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package webhook

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"gitea.dev/models/db"
	repo_model "gitea.dev/models/repo"
	user_model "gitea.dev/models/user"
	webhook_model "gitea.dev/models/webhook"
	"gitea.dev/modules/git"
	"gitea.dev/modules/glob"
	"gitea.dev/modules/graceful"
	"gitea.dev/modules/log"
	"gitea.dev/modules/optional"
	"gitea.dev/modules/queue"
	"gitea.dev/modules/setting"
	api "gitea.dev/modules/structs"
	"gitea.dev/modules/util"
	webhook_module "gitea.dev/modules/webhook"
	authz_service "gitea.dev/services/enterpriseauthz"

	"xorm.io/builder"
)

type Requester func(context.Context, *webhook_model.Webhook, *webhook_model.HookTask) (req *http.Request, body []byte, err error)

var webhookRequesters = map[webhook_module.HookType]Requester{}

func RegisterWebhookRequester(hookType webhook_module.HookType, requester Requester) {
	webhookRequesters[hookType] = requester
}

// IsValidHookTaskType returns true if a webhook registered
func IsValidHookTaskType(name string) bool {
	if name == webhook_module.GITEA || name == webhook_module.GOGS {
		return true
	}
	_, ok := webhookRequesters[name]
	return ok
}

// hookQueue is a global queue of web hooks
var hookQueue *queue.WorkerPoolQueue[int64]

// getPayloadRef returns the full ref name for hook event, if applicable.
func getPayloadRef(p api.Payloader) git.RefName {
	switch pp := p.(type) {
	case *api.CreatePayload:
		switch pp.RefType {
		case "branch":
			return git.RefNameFromBranch(pp.Ref)
		case "tag":
			return git.RefNameFromTag(pp.Ref)
		}
	case *api.DeletePayload:
		switch pp.RefType {
		case "branch":
			return git.RefNameFromBranch(pp.Ref)
		case "tag":
			return git.RefNameFromTag(pp.Ref)
		}
	case *api.PushPayload:
		return git.RefName(pp.Ref)
	}
	return ""
}

// EventSource represents the source of a webhook action. Repository and/or Owner must be set.
type EventSource struct {
	Repository *repo_model.Repository
	Owner      *user_model.User
}

// handle delivers hook tasks
func handler(items ...int64) []int64 {
	ctx := graceful.GetManager().HammerContext()

	for _, taskID := range items {
		task, err := webhook_model.GetHookTaskByID(ctx, taskID)
		if err != nil {
			if errors.Is(err, util.ErrNotExist) {
				log.Warn("GetHookTaskByID[%d] warn: %v", taskID, err)
			} else {
				log.Error("GetHookTaskByID[%d] failed: %v", taskID, err)
			}
			continue
		}

		if task.IsDelivered {
			// Already delivered in the meantime
			log.Trace("Task[%d] has already been delivered", task.ID)
			continue
		}

		if err := Deliver(ctx, task); err != nil {
			log.Error("Unable to deliver webhook task[%d]: %v", task.ID, err)
		}
	}

	return nil
}

func enqueueHookTask(ctx context.Context, taskID int64) error {
	if setting.EnterpriseAuthz.Enabled {
		task, err := webhook_model.GetHookTaskByID(ctx, taskID)
		if err != nil {
			return err
		}
		hook, err := webhook_model.GetWebhookByID(ctx, task.HookID)
		if err != nil {
			return err
		}
		if err := requireHookTaskFeature(ctx, hook, task); err != nil {
			return err
		}
	}
	if db.InTransaction(ctx) {
		db.AfterCommit(ctx, func() {
			if err := enqueueHookTask(graceful.GetManager().HammerContext(), taskID); err != nil {
				log.Error("Unable to enqueue webhook task[%d] after commit: %v", taskID, err)
			}
		})
		return nil
	}
	err := hookQueue.Push(taskID)
	if err != nil && err != queue.ErrAlreadyInQueue {
		return err
	}
	return nil
}

func checkBranchFilter(branchFilter string, ref git.RefName) bool {
	if branchFilter == "" || branchFilter == "*" || branchFilter == "**" {
		return true
	}

	g, err := glob.Compile(branchFilter)
	if err != nil {
		// should not really happen as BranchFilter is validated
		log.Debug("checkBranchFilter failed to compile filer %q, err: %s", branchFilter, err)
		return false
	}

	if ref.IsBranch() && g.Match(ref.BranchName()) {
		return true
	}
	return g.Match(ref.String())
}

// PrepareTestWebhook always creates and enqueues a hook task for manual testing.
// Unlike PrepareWebhook, it ignores event subscriptions and branch filters so the
// Test Push Event control can verify delivery even when those gates would suppress
// a real event.
func PrepareTestWebhook(ctx context.Context, w *webhook_model.Webhook, event webhook_module.HookEventType, p api.Payloader) error {
	if err := requireWebhookFeature(ctx, w, 0, 0); err != nil {
		return err
	}
	if err := requireWebhookBusinessFeature(ctx, event, w.RepoID, w.OwnerID); err != nil {
		return err
	}
	if setting.DisableWebhooks {
		return nil
	}

	payload, err := p.JSONPayload()
	if err != nil {
		return fmt.Errorf("JSONPayload for %s: %w", event, err)
	}

	task, err := webhook_model.CreateHookTask(ctx, &webhook_model.HookTask{
		HookID:         w.ID,
		PayloadContent: string(payload),
		EventType:      event,
		PayloadVersion: 2,
		SourceRepoID:   w.RepoID, SourceOwnerID: w.OwnerID, SourceResolved: true,
	})
	if err != nil {
		return fmt.Errorf("CreateHookTask for %s: %w", event, err)
	}

	return enqueueHookTask(ctx, task.ID)
}

// PrepareWebhook creates a hook task and enqueues it for processing.
// The payload is saved as-is. The adjustments depending on the webhook type happen
// right before delivery, in the [Deliver] method.
func PrepareWebhook(ctx context.Context, w *webhook_model.Webhook, event webhook_module.HookEventType, p api.Payloader) error {
	if setting.EnterpriseAuthz.Enabled && setting.EnterpriseAuthz.Enforce && w.RepoID <= 0 && w.OwnerID <= 0 {
		return &authz_service.ExecutionError{Reason: "invalid_webhook_source", Status: 403}
	}
	return prepareWebhook(ctx, w, event, p, w.RepoID, w.OwnerID)
}

func prepareWebhook(ctx context.Context, w *webhook_model.Webhook, event webhook_module.HookEventType, p api.Payloader, sourceRepoID, sourceOwnerID int64) error {
	if err := requireWebhookFeature(ctx, w, sourceRepoID, sourceOwnerID); err != nil {
		return err
	}
	if err := requireWebhookBusinessFeature(ctx, event, sourceRepoID, sourceOwnerID); err != nil {
		return err
	}
	// Skip sending if webhooks are disabled.
	if setting.DisableWebhooks {
		return nil
	}

	if !w.HasEvent(event) {
		return nil
	}

	// Avoid sending "0 new commits" to non-integration relevant webhooks (e.g. slack, discord, etc.).
	// Integration webhooks (e.g. drone) still receive the required data.
	if pushEvent, ok := p.(*api.PushPayload); ok &&
		w.Type != webhook_module.GITEA && w.Type != webhook_module.GOGS &&
		len(pushEvent.Commits) == 0 {
		return nil
	}

	// If payload has no associated branch (e.g. it's a new tag, issue, etc.), branch filter has no effect.
	if ref := getPayloadRef(p); ref != "" {
		// Check the payload's git ref against the webhook's branch filter.
		if !checkBranchFilter(w.BranchFilter, ref) {
			return nil
		}
	}

	payload, err := p.JSONPayload()
	if err != nil {
		return fmt.Errorf("JSONPayload for %s: %w", event, err)
	}

	task, err := webhook_model.CreateHookTask(ctx, &webhook_model.HookTask{
		HookID:         w.ID,
		PayloadContent: string(payload),
		EventType:      event,
		PayloadVersion: 2,
		SourceRepoID:   sourceRepoID, SourceOwnerID: sourceOwnerID, SourceResolved: true,
	})
	if err != nil {
		return fmt.Errorf("CreateHookTask for %s: %w", event, err)
	}

	return enqueueHookTask(ctx, task.ID)
}

// PrepareWebhooks adds new webhooks to task queue for given payload.
func PrepareWebhooks(ctx context.Context, source EventSource, event webhook_module.HookEventType, p api.Payloader) error {
	if setting.EnterpriseAuthz.Enabled && setting.EnterpriseAuthz.Enforce && (source.Repository == nil || source.Repository.ID <= 0) && (source.Owner == nil || source.Owner.ID <= 0) {
		return &authz_service.ExecutionError{Reason: "invalid_webhook_source", Status: 403}
	}
	owner := source.Owner

	var ws []*webhook_model.Webhook

	if source.Repository != nil {
		repoHooks, err := db.Find[webhook_model.Webhook](ctx, webhook_model.ListWebhookOptions{
			RepoID:   source.Repository.ID,
			IsActive: optional.Some(true),
		})
		if err != nil {
			return fmt.Errorf("ListWebhooksByOpts: %w", err)
		}
		ws = append(ws, repoHooks...)

		owner = source.Repository.MustOwner(ctx)
	}

	// append additional webhooks of a user or organization
	if owner != nil {
		ownerHooks, err := db.Find[webhook_model.Webhook](ctx, webhook_model.ListWebhookOptions{
			OwnerID:  owner.ID,
			IsActive: optional.Some(true),
		})
		if err != nil {
			return fmt.Errorf("ListWebhooksByOpts: %w", err)
		}
		ws = append(ws, ownerHooks...)
	}

	// Add any admin-defined system webhooks
	systemHooks, err := webhook_model.GetSystemWebhooks(ctx, optional.Some(true))
	if err != nil {
		return fmt.Errorf("GetSystemWebhooks: %w", err)
	}
	ws = append(ws, systemHooks...)

	if len(ws) == 0 {
		return nil
	}

	sourceRepoID, sourceOwnerID := int64(0), int64(0)
	if source.Repository != nil {
		sourceRepoID = source.Repository.ID
	}
	if source.Owner != nil {
		sourceOwnerID = source.Owner.ID
	} else if owner != nil {
		sourceOwnerID = owner.ID
	}
	for _, w := range ws {
		if err := prepareWebhook(ctx, w, event, p, sourceRepoID, sourceOwnerID); err != nil {
			return err
		}
	}
	return nil
}

// ReplayHookTask replays a webhook task
func ReplayHookTask(ctx context.Context, w *webhook_model.Webhook, uuid string) error {
	original, exists, err := db.Get[webhook_model.HookTask](ctx, builder.Eq{"hook_id": w.ID, "uuid": uuid})
	if err != nil {
		return err
	}
	if !exists {
		return webhook_model.ErrHookTaskNotExist{HookID: w.ID, UUID: uuid}
	}
	current, err := webhook_model.GetWebhookByID(ctx, w.ID)
	if err != nil {
		return err
	}
	if err := requireHookTaskFeature(ctx, current, original); err != nil {
		return err
	}
	task, err := webhook_model.ReplayHookTask(ctx, w.ID, uuid)
	if err != nil {
		return err
	}

	return enqueueHookTask(ctx, task.ID)
}
