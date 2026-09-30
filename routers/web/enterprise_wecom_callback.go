// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package web

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"gitea.dev/modules/timeutil"
	wecom_service "gitea.dev/services/enterprisewecom"
)

type callbackRateLimit struct {
	sync.Mutex
	tokens  float64
	updated time.Time
}

func (limit *callbackRateLimit) allow(now time.Time, capacity, perSecond float64) bool {
	limit.Lock()
	defer limit.Unlock()
	if limit.updated.IsZero() {
		limit.tokens = capacity
	} else {
		limit.tokens = min(capacity, limit.tokens+now.Sub(limit.updated).Seconds()*perSecond)
	}
	limit.updated = now
	if limit.tokens < 1 {
		return false
	}
	limit.tokens--
	return true
}

var (
	callbackRequests   callbackRateLimit
	callbackRejections callbackRateLimit
)

func AdminAuthorityCallback(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if !wecom_service.AdminCallbackEnabled() {
		http.NotFound(w, r)
		return
	}
	now := time.Now()
	reject := func(err error) {
		reason := "callback_storage_failed"
		if safe, ok := errors.AsType[*wecom_service.CallbackError](err); ok {
			reason = safe.Reason
		}
		if callbackRejections.allow(now, 1, 1) {
			wecom_service.RecordAdminCallbackOutcome(r.Context(), "rejected", reason, 0)
		}
		http.Error(w, reason, wecom_service.CallbackErrorStatus(err))
	}
	if !callbackRequests.allow(now, 200, 20) {
		w.Header().Set("Retry-After", "1")
		reject(&wecom_service.CallbackError{Status: 503, Reason: "callback_rate_limited"})
		return
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		reject(&wecom_service.CallbackError{Status: 400, Reason: "callback_malformed"})
		return
	}
	cfg := wecom_service.AdminCallbackSettings()
	switch r.Method {
	case http.MethodGet:
		challenge, err := wecom_service.VerifyAdminCallbackChallenge(cfg, query, now)
		if err != nil {
			reject(err)
			return
		}
		_, _ = io.WriteString(w, challenge)
	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, wecom_service.AdminCallbackBodyLimit)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
				reject(&wecom_service.CallbackError{Status: 413, Reason: "callback_body_too_large"})
			} else {
				reject(&wecom_service.CallbackError{Status: 400, Reason: "callback_malformed"})
			}
			return
		}
		callback, err := wecom_service.VerifyAdminCallbackEvent(cfg, query, body, now)
		if err != nil {
			reject(err)
			return
		}
		if _, err = wecom_service.AcceptAdminCallback(r.Context(), callback, timeutil.TimeStamp(now.Unix())); err != nil {
			reject(err)
			return
		}
		_, _ = io.WriteString(w, "success")
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
