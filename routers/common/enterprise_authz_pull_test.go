// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package common

import (
	stdcontext "context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"gitea.dev/modules/reqctx"
	"gitea.dev/services/context"

	"github.com/stretchr/testify/require"
)

func TestPullGuardFormIDDoesNotReadUnsupportedBodies(t *testing.T) {
	body := &guardUnreadBody{}
	req := httptest.NewRequest(http.MethodPost, "/", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	base := &context.Base{RequestContext: reqctx.NewRequestContextForTest(t), Req: req, Resp: context.WrapResponseWriter(httptest.NewRecorder())}
	ctx, cancel := stdcontext.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	id, err := pullGuardFormID(ctx, base, "comment_id")
	require.Error(t, err)
	require.Zero(t, id)
	require.False(t, body.read)
}

type guardUnreadBody struct{ read bool }

func (r *guardUnreadBody) Read([]byte) (int, error) {
	r.read = true
	return 0, errors.New("must_not_read")
}

func TestPullGuardFormIDHonorsStreamDeadlineAndSizeLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ctx, cancel := stdcontext.WithTimeout(req.Context(), 50*time.Millisecond)
		defer cancel()
		base := &context.Base{RequestContext: reqctx.NewRequestContextForTest(t), Req: req, Resp: context.WrapResponseWriter(w)}
		id, err := pullGuardFormID(ctx, base, "comment_id")
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
		} else {
			_, _ = io.WriteString(w, "id="+strconv.FormatInt(id, 10))
		}
	}))
	defer server.Close()
	response, err := http.Post(server.URL, "application/x-www-form-urlencoded", strings.NewReader("comment_id=7"))
	require.NoError(t, err)
	require.Equal(t, 200, response.StatusCode)
	require.NoError(t, response.Body.Close())
	response, err = http.Post(server.URL, "application/x-www-form-urlencoded", strings.NewReader("comment_id=7&content="+strings.Repeat("x", 64<<10)))
	require.NoError(t, err)
	require.Equal(t, 400, response.StatusCode)
	require.NoError(t, response.Body.Close())
	reader, writer := io.Pipe()
	t.Cleanup(func() { _ = reader.Close(); _ = writer.Close() })
	done := make(chan int, 1)
	go func() {
		response, err := http.Post(server.URL, "application/x-www-form-urlencoded", reader)
		if err != nil {
			done <- 0
			return
		}
		defer response.Body.Close()
		done <- response.StatusCode
	}()
	_, err = io.WriteString(writer, "comment_id=")
	require.NoError(t, err)
	select {
	case status := <-done:
		require.Equal(t, 400, status)
	case <-time.After(time.Second):
		t.Fatal("guard form parser exceeded its deadline")
	}
	require.NoError(t, writer.Close())
}

func TestPullGuardFormIDPreservesWrittenNativeDenial(t *testing.T) {
	type parsedTarget struct {
		id  int64
		err error
	}
	parsed := make(chan parsedTarget, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ctx, cancel := stdcontext.WithTimeout(req.Context(), 50*time.Millisecond)
		defer cancel()
		base := &context.Base{RequestContext: reqctx.NewRequestContextForTest(t), Req: req, Resp: context.WrapResponseWriter(w)}
		base.Status(http.StatusNotFound)
		_, _ = base.Write([]byte("native denial"))
		id, err := pullGuardFormID(ctx, base, "comment_id")
		parsed <- parsedTarget{id: id, err: err}
	}))
	defer server.Close()
	check := func(body io.Reader, valid bool) {
		response, err := http.Post(server.URL, "application/x-www-form-urlencoded", body)
		require.NoError(t, err)
		defer response.Body.Close()
		contents, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		require.Equal(t, http.StatusNotFound, response.StatusCode)
		require.Equal(t, "native denial", string(contents))
		result := <-parsed
		if valid {
			require.NoError(t, result.err)
			require.EqualValues(t, 7, result.id)
		} else {
			require.Error(t, result.err)
		}
	}
	check(strings.NewReader("comment_id=7"), true)
	check(strings.NewReader("comment_id=7&content="+strings.Repeat("x", 64<<10)), false)
	reader, writer := io.Pipe()
	t.Cleanup(func() { _ = reader.Close(); _ = writer.Close() })
	done := make(chan struct{})
	go func() { defer close(done); check(reader, false) }()
	_, err := io.WriteString(writer, "comment_id=")
	require.NoError(t, err)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("shadow parser blocked the native denial")
	}
	require.NoError(t, writer.Close())
}

func TestLifecycleGuardActionUsesOnlyBoundedTypedInput(t *testing.T) {
	for _, jsonBody := range []bool{false, true} {
		body := &guardUnreadBody{}
		req := httptest.NewRequest(http.MethodPost, "/", body)
		contentType := "application/x-www-form-urlencoded"
		if jsonBody {
			contentType = "application/json"
		}
		req.Header.Set("Content-Type", contentType)
		base := &context.Base{RequestContext: reqctx.NewRequestContextForTest(t), Req: req, Resp: context.WrapResponseWriter(httptest.NewRecorder())}
		ctx, cancel := stdcontext.WithTimeout(t.Context(), 50*time.Millisecond)
		action, err := nativeLifecycleGuardActions(ctx, base, jsonBody)
		cancel()
		require.Error(t, err)
		require.Empty(t, action)
		require.False(t, body.read)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ctx, cancel := stdcontext.WithTimeout(req.Context(), 50*time.Millisecond)
		defer cancel()
		base := &context.Base{RequestContext: reqctx.NewRequestContextForTest(t), Req: req, Resp: context.WrapResponseWriter(w)}
		action, err := nativeLifecycleGuardActions(ctx, base, req.Header.Get("Content-Type") == "application/json")
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var keys []string
		for _, key := range action {
			keys = append(keys, string(key))
		}
		_, _ = io.WriteString(w, strings.Join(keys, ","))
	}))
	defer server.Close()
	for _, tc := range []struct {
		contentType, body, action string
		status                    int
	}{
		{"application/x-www-form-urlencoded", "action=transfer", "repo.transfer", 200},
		{"application/x-www-form-urlencoded", "action=advanced", "", 200},
		{"application/json", `{"archived":false}`, "repo.archive", 200},
		{"application/json", `{"archived":true,"authz_action":"repo.delete"}`, "repo.archive", 200},
		{"application/json", `{"description":"not archive"}`, "", 200},
		{"application/json", `{"archived":"true"}`, "", 200},
		{"application/json", `{"archived":true,"padding":"` + strings.Repeat("x", 64<<10) + `"}`, "", 400},
	} {
		response, err := http.Post(server.URL, tc.contentType, strings.NewReader(tc.body))
		require.NoError(t, err)
		require.Equal(t, tc.status, response.StatusCode)
		body, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		require.Equal(t, tc.action, string(body))
		require.NoError(t, response.Body.Close())
	}
	reader, writer := io.Pipe()
	t.Cleanup(func() { _ = reader.Close(); _ = writer.Close() })
	done := make(chan int, 1)
	go func() {
		response, err := http.Post(server.URL, "application/json", reader)
		if err != nil {
			done <- 0
			return
		}
		defer response.Body.Close()
		done <- response.StatusCode
	}()
	_, err := io.WriteString(writer, `{"archived":`)
	require.NoError(t, err)
	select {
	case status := <-done:
		require.Equal(t, 400, status)
	case <-time.After(time.Second):
		t.Fatal("lifecycle guard parser exceeded deadline")
	}
	require.NoError(t, writer.Close())
}
