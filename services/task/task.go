// Copyright 2019 Gitea. All rights reserved.
// SPDX-License-Identifier: MIT

package task

import (
	"context"
	"errors"
	"fmt"

	admin_model "gitea.dev/models/admin"
	repo_model "gitea.dev/models/repo"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/graceful"
	"gitea.dev/modules/json"
	"gitea.dev/modules/log"
	base "gitea.dev/modules/migration"
	"gitea.dev/modules/queue"
	"gitea.dev/modules/secret"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/structs"
	"gitea.dev/modules/timeutil"
	"gitea.dev/modules/util"
	authz_service "gitea.dev/services/enterpriseauthz"
	repo_service "gitea.dev/services/repository"
)

// taskQueue is a global queue of tasks
var taskQueue *queue.WorkerPoolQueue[*admin_model.Task]

// Run a task
func Run(ctx context.Context, t *admin_model.Task) error {
	switch t.Type {
	case structs.TaskTypeMigrateRepo:
		return runMigrateTask(ctx, t)
	default:
		return fmt.Errorf("Unknown task type: %d", t.Type)
	}
}

// Init will start the service to get all unfinished tasks and run them
func Init() error {
	taskQueue = queue.CreateSimpleQueue(graceful.GetManager().ShutdownContext(), "task", handler)
	if taskQueue == nil {
		return errors.New("unable to create task queue")
	}
	go graceful.GetManager().RunWithCancel(taskQueue)
	return nil
}

func handler(items ...*admin_model.Task) []*admin_model.Task {
	for _, task := range items {
		if err := Run(graceful.GetManager().ShutdownContext(), task); err != nil {
			log.Error("Run task failed: %v", err)
		}
	}
	return nil
}

// MigrateRepository add migration repository to task
func MigrateRepository(ctx context.Context, doer, u *user_model.User, opts base.MigrateOptions) error {
	task, err := CreateMigrateTask(ctx, doer, u, opts)
	if err != nil {
		return err
	}

	return taskQueue.Push(task)
}

// CreateMigrateTask creates a migrate task
func CreateMigrateTask(ctx context.Context, doer, u *user_model.User, opts base.MigrateOptions) (_ *admin_model.Task, retErr error) {
	ctx = authz_service.WithOperation(authz_service.WithMigrationSource(ctx, "system"))
	stage, reason := "prepare_task", "task_preparation_failed"
	targetCreated := false
	defer func() {
		if retErr != nil && !targetCreated {
			if stage == "create_target" {
				reason = authz_service.MigrationTargetFailureReason(retErr)
			}
			authz_service.RecordMigrationFailure(ctx, doer, u.ID, stage, reason)
		}
	}()
	// encrypt credentials for persistence
	var err error
	opts.CloneAddrEncrypted, err = secret.EncryptSecret(setting.SecretKey, opts.CloneAddr)
	if err != nil {
		return nil, err
	}
	opts.CloneAddr = util.SanitizeCredentialURLs(opts.CloneAddr)
	opts.AuthPasswordEncrypted, err = secret.EncryptSecret(setting.SecretKey, opts.AuthPassword)
	if err != nil {
		return nil, err
	}
	opts.AuthPassword = ""
	opts.AuthTokenEncrypted, err = secret.EncryptSecret(setting.SecretKey, opts.AuthToken)
	if err != nil {
		return nil, err
	}
	opts.AuthToken = ""
	opts.AWSSecretAccessKeyEncrypted, err = secret.EncryptSecret(setting.SecretKey, opts.AWSSecretAccessKey)
	if err != nil {
		return nil, err
	}
	opts.AWSSecretAccessKey = ""
	bs, err := json.Marshal(&opts)
	if err != nil {
		return nil, err
	}

	task := &admin_model.Task{
		DoerID:         doer.ID,
		OwnerID:        u.ID,
		Type:           structs.TaskTypeMigrateRepo,
		Status:         structs.TaskStatusQueued,
		PayloadContent: string(bs),
	}

	reason = "task_creation_failed"
	if err := admin_model.CreateTask(ctx, task); err != nil {
		return nil, err
	}

	stage = "create_target"
	repo, err := repo_service.CreateRepositoryDirectly(ctx, doer, u, repo_service.CreateRepoOptions{
		Name:           opts.RepoName,
		Description:    opts.Description,
		OriginalURL:    opts.OriginalURL,
		GitServiceType: opts.GitServiceType,
		IsPrivate:      opts.Private || setting.Repository.ForcePrivate,
		IsMirror:       opts.Mirror,
		Status:         repo_model.RepositoryBeingMigrated,
	}, false)
	if err != nil {
		task.EndTime = timeutil.TimeStampNow()
		task.Status = structs.TaskStatusFailed
		err2 := task.UpdateCols(ctx, "end_time", "status")
		if err2 != nil {
			log.Error("UpdateCols Failed: %v", err2.Error())
		}
		return nil, err
	}

	targetCreated = true
	task.RepoID = repo.ID
	if err = task.UpdateCols(ctx, "repo_id"); err != nil {
		authz_service.ObserveQueuedMigration(ctx, doer, repo, authz_service.NativeFailed, nil)
		return nil, err
	}
	authz_service.ObserveQueuedMigration(ctx, doer, repo, authz_service.NativeUnknown, func(bounded context.Context, ticket authz.HookOperationTicket) error {
		opts.AuthzOperation = ticket
		payload, err := json.Marshal(&opts)
		if err != nil {
			return err
		}
		previous := task.PayloadContent
		task.PayloadContent = string(payload)
		if err := task.UpdateCols(bounded, "payload_content"); err != nil {
			task.PayloadContent = previous
			return err
		}
		return nil
	})
	return task, nil
}

// RetryMigrateTask retry a migrate task
func RetryMigrateTask(ctx context.Context, repoID int64) error {
	migratingTask, err := admin_model.GetMigratingTask(ctx, repoID)
	if err != nil {
		log.Error("GetMigratingTask: %v", err)
		return err
	}
	if migratingTask.Status == structs.TaskStatusQueued || migratingTask.Status == structs.TaskStatusRunning {
		return nil
	}

	// TODO Need to removing the storage/database garbage brought by the failed task

	// Reset task status and messages
	migratingTask.Status = structs.TaskStatusQueued
	migratingTask.Message = ""
	if err = migratingTask.UpdateCols(ctx, "status", "message"); err != nil {
		log.Error("task.UpdateCols failed: %v", err)
		return err
	}

	authz_service.ObserveQueuedMigration(authz_service.WithMigrationSource(ctx, "system"), &user_model.User{ID: migratingTask.DoerID}, &repo_model.Repository{ID: migratingTask.RepoID}, authz_service.NativeUnknown, func(bounded context.Context, ticket authz.HookOperationTicket) error {
		if len(migratingTask.PayloadContent) > authz.MaxSnapshotBytes {
			return errors.New("migration_payload_limit")
		}
		var opts base.MigrateOptions
		if err := json.Unmarshal([]byte(migratingTask.PayloadContent), &opts); err != nil {
			return err
		}
		opts.AuthzOperation = ticket
		payload, err := json.Marshal(&opts)
		if err != nil {
			return err
		}
		previous := migratingTask.PayloadContent
		migratingTask.PayloadContent = string(payload)
		if err := migratingTask.UpdateCols(bounded, "payload_content"); err != nil {
			migratingTask.PayloadContent = previous
			return err
		}
		return nil
	})
	return taskQueue.Push(migratingTask)
}
