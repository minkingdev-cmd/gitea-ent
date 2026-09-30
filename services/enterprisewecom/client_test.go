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

	"gitea.dev/modules/json"

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

func TestClientListAppAdminsUsesSuiteAccessTokenAndClassifiesResponse(t *testing.T) {
	client := NewClient(Config{
		CorpID:           "corp-1",
		AgentID:          "1000002",
		SuiteAccessToken: "suite-token",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			require.Equal(t, http.MethodPost, req.Method)
			require.Equal(t, "/cgi-bin/service/get_admin_list", req.URL.Path)
			require.Equal(t, "suite-token", req.URL.Query().Get("suite_access_token"))
			var body map[string]any
			require.NoError(t, json.NewDecoder(req.Body).Decode(&body))
			require.Equal(t, "corp-1", body["auth_corpid"])
			require.EqualValues(t, 1000002, body["agentid"])
			return jsonResponse(`{"errcode":0,"admin":[{"userid":"zhang.super","open_userid":"open-zhang","auth_type":1},{"userid":"bot.notice","auth_type":0}]}`), nil
		})},
	})

	admins, err := client.ListAppAdmins(t.Context())
	require.NoError(t, err)
	require.Len(t, admins, 2)
	require.Equal(t, "zhang.super", admins[0].UserID)
	require.Equal(t, "open-zhang", admins[0].OpenUserID)
	require.Equal(t, 1, admins[0].AuthType)
	require.Equal(t, "bot.notice", admins[1].UserID)
	require.Equal(t, 0, admins[1].AuthType)
}

func TestClientListAppAdminsUsesSuperAdminTagWhenSuiteAccessTokenIsUnavailable(t *testing.T) {
	client := NewClient(Config{
		CorpID:            "corp-1",
		CorpSecret:        "secret-1",
		AgentID:           "1000002",
		SuperAdminTagName: "超管",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			switch req.URL.Path {
			case "/cgi-bin/gettoken":
				require.Equal(t, "corp-1", req.URL.Query().Get("corpid"))
				require.Equal(t, "secret-1", req.URL.Query().Get("corpsecret"))
				return jsonResponse(`{"errcode":0,"access_token":"token-1","expires_in":7200}`), nil
			case "/cgi-bin/tag/list":
				require.Equal(t, "token-1", req.URL.Query().Get("access_token"))
				return jsonResponse(`{"errcode":0,"taglist":[{"tagid":7,"tagname":"研发"},{"tagid":9,"tagname":"超管"}]}`), nil
			case "/cgi-bin/tag/get":
				require.Equal(t, "token-1", req.URL.Query().Get("access_token"))
				require.Equal(t, "9", req.URL.Query().Get("tagid"))
				return jsonResponse(`{"errcode":0,"tagname":"超管","userlist":[{"userid":"zhang.super"},{"userid":"wang.super"}],"partylist":[42]}`), nil
			default:
				return &http.Response{StatusCode: http.StatusNotFound, Body: http.NoBody}, nil
			}
		})},
	})

	admins, err := client.ListAppAdmins(t.Context())
	require.NoError(t, err)
	require.Equal(t, []AppAdminInfo{
		{UserID: "zhang.super", AuthType: 1},
		{UserID: "wang.super", AuthType: 1},
	}, admins)
}

func TestClientListAppAdminsRejectsMissingSuperAdminTag(t *testing.T) {
	client := NewClient(Config{
		CorpID:            "corp-1",
		CorpSecret:        "secret-1",
		AgentID:           "1000002",
		SuperAdminTagName: "超管",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			switch req.URL.Path {
			case "/cgi-bin/gettoken":
				return jsonResponse(`{"errcode":0,"access_token":"token-1","expires_in":7200}`), nil
			case "/cgi-bin/tag/list":
				return jsonResponse(`{"errcode":0,"taglist":[{"tagid":7,"tagname":"研发"}]}`), nil
			default:
				t.Fatalf("unexpected WeCom request path %s", req.URL.Path)
				return nil, errors.New("unexpected request path")
			}
		})},
	})

	admins, err := client.ListAppAdmins(t.Context())
	require.Error(t, err)
	require.Empty(t, admins)
}

func TestClientListAppAdminsRequiresSupportedAuthoritySource(t *testing.T) {
	client := NewClient(Config{CorpID: "corp-1", AgentID: "1000002"})
	_, err := client.ListAppAdmins(t.Context())
	require.ErrorIs(t, err, ErrWeComAuthorityUnsupported)
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

func TestClientRequiresExplicitProviderSuccess(t *testing.T) {
	for _, tc := range []struct {
		name    string
		path    string
		payload string
		call    func(*Client) error
	}{
		{"token", "/cgi-bin/gettoken", `"access_token":"token-1","expires_in":7200`, func(c *Client) error { _, err := c.GetAccessToken(t.Context()); return err }},
		{"identity", "/cgi-bin/auth/getuserinfo", `"userid":"user-1"`, func(c *Client) error { _, err := c.GetUserInfo(t.Context(), "token-1", "code-1"); return err }},
		{"authority", "/cgi-bin/service/get_admin_list", `"admin":[]`, func(c *Client) error { _, err := c.ListAppAdmins(t.Context()); return err }},
		{"departments", "/cgi-bin/department/list", `"department":[]`, func(c *Client) error { _, err := c.ListDepartments(t.Context()); return err }},
		{"department_detail", "/cgi-bin/department/get", `"department":{"id":1}`, func(c *Client) error { _, err := c.GetDepartment(t.Context(), 1); return err }},
		{"members", "/cgi-bin/user/list", `"userlist":[]`, func(c *Client) error { _, err := c.ListMembers(t.Context(), 1); return err }},
		{"tags", "/cgi-bin/tag/list", `"taglist":[]`, func(c *Client) error { _, err := c.ListTags(t.Context()); return err }},
		{"tag_members", "/cgi-bin/tag/get", `"userlist":[]`, func(c *Client) error { _, err := c.ListTagMembers(t.Context(), 1); return err }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, code := range []struct {
				name, field string
				success     bool
			}{
				{"missing", "", false},
				{"null", `"errcode":null,`, false},
				{"zero", `"errcode":0,`, true},
			} {
				t.Run(code.name, func(t *testing.T) {
					client := NewClient(Config{CorpID: "corp-1", AgentID: "1", SuiteAccessToken: "suite-token", HTTPClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
						if req.URL.Path == tc.path {
							return jsonResponse("{" + code.field + tc.payload + `,"errmsg":"provider-sensitive"}`), nil
						}
						require.Equal(t, "/cgi-bin/gettoken", req.URL.Path)
						return jsonResponse(`{"errcode":0,"access_token":"token-1","expires_in":7200}`), nil
					})}})
					err := tc.call(client)
					if code.success {
						require.NoError(t, err)
						return
					}
					require.ErrorIs(t, err, ErrWeComUnavailable)
					require.NotContains(t, err.Error(), "provider-sensitive")
				})
			}
		})
	}
}
