// Copyright 2017 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package repo

import (
	"gitea.dev/services/context"
	issue_service "gitea.dev/services/issue"
	notify_service "gitea.dev/services/notify"
)

// IssueStartStopwatch creates a stopwatch for the given issue.
func IssueStartStopwatch(c *context.Context) {
	issue := GetActionIssue(c)
	if c.Written() {
		return
	}

	if !c.Repo.CanUseTimetracker(c, issue, c.Doer) {
		c.NotFound(nil)
		return
	}

	if ok, err := issue_service.CreateIssueStopwatch(c, c.Doer, issue); err != nil {
		c.ServerError("CreateIssueStopwatch", err)
		return
	} else if !ok {
		c.Flash.Warning(c.Tr("repo.issues.stopwatch_already_created"))
	} else {
		c.Flash.Success(c.Tr("repo.issues.tracker_auto_close"))
		notify_service.StopwatchChanged(c, c.Doer)
	}
	c.JSONRedirect("")
}

// IssueStopStopwatch stops a stopwatch for the given issue.
func IssueStopStopwatch(c *context.Context) {
	issue := GetActionIssue(c)
	if c.Written() {
		return
	}

	if !c.Repo.CanUseTimetracker(c, issue, c.Doer) {
		c.NotFound(nil)
		return
	}

	if ok, err := issue_service.FinishIssueStopwatch(c, c.Doer, issue); err != nil {
		c.ServerError("FinishIssueStopwatch", err)
		return
	} else if !ok {
		c.Flash.Warning(c.Tr("repo.issues.stopwatch_already_stopped"))
	} else {
		notify_service.StopwatchChanged(c, c.Doer)
	}
	c.JSONRedirect("")
}

// CancelStopwatch cancel the stopwatch
func CancelStopwatch(c *context.Context) {
	issue := GetActionIssue(c)
	if c.Written() {
		return
	}
	if !c.Repo.CanUseTimetracker(c, issue, c.Doer) {
		c.NotFound(nil)
		return
	}

	if _, err := issue_service.CancelStopwatch(c, c.Doer, issue); err != nil {
		c.ServerError("CancelStopwatch", err)
		return
	}

	notify_service.StopwatchChanged(c, c.Doer)
	c.JSONRedirect("")
}
