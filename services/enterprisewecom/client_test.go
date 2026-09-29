// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterprisewecom

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func jsonResponse(body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func TestClientResolveOAuthUser(t *testing.T) {
	client := NewClient(Config{
		CorpID:     "corp-1",
		CorpSecret: "secret-1",
		AgentID:    "1000002",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			switch req.URL.Path {
			case "/cgi-bin/gettoken":
				require.Equal(t, "corp-1", req.URL.Query().Get("corpid"))
				require.Equal(t, "secret-1", req.URL.Query().Get("corpsecret"))
				return jsonResponse(`{"errcode":0,"access_token":"token-1","expires_in":7200}`), nil
			case "/cgi-bin/auth/getuserinfo":
				require.Equal(t, "token-1", req.URL.Query().Get("access_token"))
				require.Equal(t, "code-1", req.URL.Query().Get("code"))
				return jsonResponse(`{"errcode":0,"userid":"zhangsan","user_ticket":"ticket"}`), nil
			default:
				return &http.Response{StatusCode: http.StatusNotFound, Body: http.NoBody}, nil
			}
		})},
	})

	member, err := client.ResolveOAuthUser(t.Context(), "code-1")
	require.NoError(t, err)
	require.Equal(t, "corp-1", member.CorpID)
	require.Equal(t, "1000002", member.AgentID)
	require.Equal(t, "zhangsan", member.UserID)
}

func TestClientResolveOAuthUserDeniesProviderError(t *testing.T) {
	client := NewClient(Config{
		CorpID: "corp-1", CorpSecret: "secret-1", AgentID: "1000002",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == "/cgi-bin/gettoken" {
				return jsonResponse(`{"errcode":0,"access_token":"token-1","expires_in":7200}`), nil
			}
			return jsonResponse(`{"errcode":40029,"errmsg":"invalid code secret-1"}`), nil
		})},
	})

	_, err := client.ResolveOAuthUser(t.Context(), "bad-code")
	require.ErrorIs(t, err, ErrWeComDenied)
	require.NotContains(t, err.Error(), "secret-1")
	require.NotContains(t, err.Error(), "invalid code")
	require.Contains(t, err.Error(), "40029")
}

func TestClientTransportErrorDoesNotExposeRequestURL(t *testing.T) {
	client := NewClient(Config{
		CorpID: "corp-sensitive", CorpSecret: "secret-sensitive", AgentID: "1000002",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return nil, &url.Error{Op: req.Method, URL: req.URL.String(), Err: errors.New("network failed")}
		})},
	})

	_, err := client.ResolveOAuthUser(t.Context(), "code-sensitive")
	require.ErrorIs(t, err, ErrWeComUnavailable)
	for _, sensitive := range []string{"corp-sensitive", "secret-sensitive", "code-sensitive", "corpsecret=", "access_token=", "code="} {
		require.NotContains(t, err.Error(), sensitive)
	}
}

func TestClientReusesAccessToken(t *testing.T) {
	var tokenRequests atomic.Int32
	client := NewClient(Config{
		CorpID: "corp-1", CorpSecret: "secret-1", AgentID: "1000002",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			tokenRequests.Add(1)
			return jsonResponse(`{"errcode":0,"access_token":"token-1","expires_in":7200}`), nil
		})},
	})

	_, err := client.GetAccessToken(t.Context())
	require.NoError(t, err)
	_, err = client.GetAccessToken(t.Context())
	require.NoError(t, err)
	require.Equal(t, int32(1), tokenRequests.Load())
}

func TestClientPropagatesCancellation(t *testing.T) {
	client := NewClient(Config{
		CorpID: "corp-1", CorpSecret: "secret-1", AgentID: "1000002",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			<-req.Context().Done()
			return nil, req.Context().Err()
		})},
	})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := client.GetAccessToken(ctx)
	require.ErrorIs(t, err, context.Canceled)
}
