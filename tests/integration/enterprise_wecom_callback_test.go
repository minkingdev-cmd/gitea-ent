// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gitea.dev/models/db"
	wecom_model "gitea.dev/models/enterprisewecom"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"
	"gitea.dev/tests"

	"github.com/stretchr/testify/require"
)

func encryptedAdminCallbackRequest(t *testing.T, plain, random string, now int64) (string, string) {
	t.Helper()
	cfg := setting.EnterpriseWeCom
	key, err := base64.StdEncoding.DecodeString(cfg.AdminCallbackAESKey + "=")
	require.NoError(t, err)
	data := append([]byte(random), 0, 0, 0, 0)
	binary.BigEndian.PutUint32(data[16:20], uint32(len(plain)))
	data = append(data, []byte(plain+cfg.AdminCallbackReceiverID)...)
	padding := 32 - len(data)%32
	data = append(data, bytes.Repeat([]byte{byte(padding)}, padding)...)
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	cipher.NewCBCEncrypter(block, key[:16]).CryptBlocks(data, data)
	encrypted := base64.StdEncoding.EncodeToString(data)
	q := url.Values{"timestamp": {strconv.FormatInt(now, 10)}, "nonce": {random}}
	parts := []string{cfg.AdminCallbackToken, q.Get("timestamp"), random, encrypted}
	sort.Strings(parts)
	digest := sha1.Sum([]byte(strings.Join(parts, "")))
	q.Set("msg_signature", hex.EncodeToString(digest[:]))
	return q.Encode(), encrypted
}

func TestEnterpriseWeComCallbackProviderRoute(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	var calls atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer provider.Close()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{Enabled: true, LoginOnly: true, CorpID: "callback-corp", AgentID: "1000002", AdminCallbackToken: "callback-token", AdminCallbackAESKey: "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG", AdminCallbackReceiverID: "callback-receiver", APIBaseURL: provider.URL})()
	path := "/enterprise/wecom/callback/admin-authority"
	MakeRequest(t, NewRequest(t, "GET", path), http.StatusNotFound)
	setting.EnterpriseWeCom.AdminCallbackEnabled = true
	now := time.Now().Unix()
	q, enc := encryptedAdminCallbackRequest(t, "challenge-text", "1234567890123456", now)
	challenge := MakeRequest(t, NewRequest(t, "GET", path+"?"+q+"&echostr="+url.QueryEscape(enc)), http.StatusOK)
	require.Equal(t, "challenge-text", challenge.Body.String())
	require.Empty(t, challenge.Header().Values("Set-Cookie"))
	event := `<xml><AuthCorpId>callback-corp</AuthCorpId><AgentID>1000002</AgentID><InfoType>change_app_admin</InfoType><TimeStamp>` + strconv.FormatInt(now, 10) + `</TimeStamp><NewAdminUserID>untrusted-admin</NewAdminUserID></xml>`
	for _, random := range []string{"1234567890123456", "abcdefghijklmnop"} {
		q, enc = encryptedAdminCallbackRequest(t, event, random, now)
		resp := MakeRequest(t, NewRequestWithBody(t, "POST", path+"?"+q, strings.NewReader(`<xml><Encrypt>`+enc+`</Encrypt><AgentID>outer-ignored</AgentID></xml>`)).SetHeader("Sec-Fetch-Site", "cross-site").SetHeader("Origin", "https://provider.invalid"), http.StatusOK)
		require.Equal(t, "success", resp.Body.String())
		require.Empty(t, resp.Header().Values("Set-Cookie"))
	}
	count, err := db.GetEngine(t.Context()).Count(new(wecom_model.CallbackReceipt))
	require.NoError(t, err)
	require.EqualValues(t, 1, count)
	MakeRequest(t, NewRequestWithBody(t, "POST", path+"?"+q+"&nonce=duplicate", strings.NewReader(`<xml><Encrypt>`+enc+`</Encrypt></xml>`)), http.StatusBadRequest)
	badEvent := strings.ReplaceAll(event, "<AgentID>1000002</AgentID>", "")
	badQuery, badEnc := encryptedAdminCallbackRequest(t, badEvent, "1234567890123456", now)
	MakeRequest(t, NewRequestWithBody(t, "POST", path+"?"+badQuery, strings.NewReader(`<xml><Encrypt>`+badEnc+`</Encrypt><AgentID>1000002</AgentID></xml>`)), http.StatusForbidden)
	MakeRequest(t, NewRequestWithBody(t, "POST", path, strings.NewReader(strings.Repeat("x", 1<<20+1))), http.StatusRequestEntityTooLarge)
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	failed := NewRequestWithBody(t, "POST", path+"?"+q, strings.NewReader(`<xml><Encrypt>`+enc+`</Encrypt></xml>`))
	failed.Request = failed.Request.WithContext(canceled)
	MakeRequest(t, failed, http.StatusServiceUnavailable)
	require.Zero(t, calls.Load())
	authority, err := db.GetEngine(t.Context()).Count(new(wecom_model.AdminAuthority))
	require.NoError(t, err)
	require.Zero(t, authority)
	// 唯一provider路径例外不能让相邻管理路径或API alias也绕过认证。
	MakeRequest(t, NewRequest(t, "POST", "/api/v1/enterprise/wecom/callback/admin-authority"), http.StatusNotFound)
}
