// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterprisewecom

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"gitea.dev/models/unittest"

	"github.com/stretchr/testify/require"
)

func callbackTestConfig() AdminCallbackConfig {
	return AdminCallbackConfig{Token: "QDG6eK", AESKey: "jWmYm7qr5nMoAUwZRjGtBxmz3KA1tkAj3ykkR6q2B2C", ReceiverID: "wx5823bf96d3bd56c7", CorpID: "corp-auth", AgentID: "1000002"}
}

func callbackTestEncrypted(t *testing.T, plain, receiver, random string) string {
	t.Helper()
	key, err := base64.StdEncoding.DecodeString(callbackTestConfig().AESKey + "=")
	require.NoError(t, err)
	data := append([]byte(random), 0, 0, 0, 0)
	binary.BigEndian.PutUint32(data[16:20], uint32(len(plain)))
	data = append(data, []byte(plain+receiver)...)
	padding := 32 - len(data)%32
	data = append(data, bytes.Repeat([]byte{byte(padding)}, padding)...)
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	cipher.NewCBCEncrypter(block, key[:16]).CryptBlocks(data, data)
	return base64.StdEncoding.EncodeToString(data)
}

func callbackTestQuery(ciphertext string) url.Values {
	q := url.Values{"timestamp": {"1780000000"}, "nonce": {"test-nonce"}}
	parts := []string{callbackTestConfig().Token, q.Get("timestamp"), q.Get("nonce"), ciphertext}
	sort.Strings(parts)
	hash := sha1.Sum([]byte(strings.Join(parts, "")))
	q.Set("msg_signature", hex.EncodeToString(hash[:]))
	return q
}

const callbackTestEvent = `<xml><AuthCorpId>corp-auth</AuthCorpId><AgentID>1000002</AgentID><InfoType>change_app_admin</InfoType><TimeStamp>1780000000</TimeStamp><NewAdminUserID>attacker@example.org</NewAdminUserID></xml>`

func TestAdminCallbackOfficialURLVector(t *testing.T) {
	// 企业微信官方样例历史版本 f2c836f57187c5390546a70e99be54251c56a95c。
	q := url.Values{"msg_signature": {"5c45ff5e21c57e6ad56bac8758b79b1d9ac89fd3"}, "timestamp": {"1409659589"}, "nonce": {"263014780"}, "echostr": {"P9nAzCzyDtyTWESHep1vC5X9xho/qYX3Zpb4yKa9SKld1DsH3Iyt3tP3zNdtp+4RPcs8TgAE7OaBO+FZXvnaqQ=="}}
	challenge, err := VerifyAdminCallbackChallenge(callbackTestConfig(), q, time.Unix(1409659589, 0))
	require.NoError(t, err)
	require.Equal(t, "1616140317555161061", challenge)
}

func TestAdminCallbackVerifierBoundaryAndCanonicalDedup(t *testing.T) {
	cfg := callbackTestConfig()
	now := time.Unix(1780000000, 0)
	encrypted := callbackTestEncrypted(t, callbackTestEvent, cfg.ReceiverID, "1234567890123456")
	valid, err := VerifyAdminCallbackEvent(cfg, callbackTestQuery(encrypted), []byte(`<xml><Encrypt>`+encrypted+`</Encrypt><AgentID>untrusted</AgentID></xml>`), now)
	require.NoError(t, err)
	again := callbackTestEncrypted(t, strings.ReplaceAll(callbackTestEvent, "><", ">\n<"), cfg.ReceiverID, "abcdefghijklmnop")
	duplicate, err := VerifyAdminCallbackEvent(cfg, callbackTestQuery(again), []byte(`<xml><Encrypt>`+again+`</Encrypt></xml>`), now)
	require.NoError(t, err)
	require.Equal(t, valid.dedupKey, duplicate.dedupKey)
	cases := []struct {
		name, plain, receiver string
		query                 func(url.Values)
		status                int
	}{
		{name: "missing corp", plain: strings.ReplaceAll(callbackTestEvent, "<AuthCorpId>corp-auth</AuthCorpId>", ""), status: 403},
		{name: "missing agent", plain: strings.ReplaceAll(callbackTestEvent, "<AgentID>1000002</AgentID>", ""), status: 403},
		{name: "wrong corp", plain: strings.ReplaceAll(callbackTestEvent, "corp-auth", "other"), status: 403},
		{name: "wrong agent", plain: strings.ReplaceAll(callbackTestEvent, "1000002", "wrong"), status: 403},
		{name: "wrong receiver", receiver: "wrong", status: 403},
		{name: "event", plain: strings.ReplaceAll(callbackTestEvent, "change_app_admin", "change_contact"), status: 400},
		{name: "duplicate field", plain: strings.ReplaceAll(callbackTestEvent, "</xml>", "<AgentID>1000002</AgentID></xml>"), status: 400},
		{name: "duplicate query", query: func(q url.Values) { q.Add("nonce", "other") }, status: 400},
		{name: "bad signature", query: func(q url.Values) { q.Set("msg_signature", strings.Repeat("0", 40)) }, status: 403},
		{name: "expired", query: func(q url.Values) { q.Set("timestamp", "1779999399") }, status: 403},
		{name: "future", query: func(q url.Values) { q.Set("timestamp", "1780000061") }, status: 403},
		{name: "old signed event", plain: strings.ReplaceAll(callbackTestEvent, "1780000000", "1779999399"), status: 403},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plain := tc.plain
			if plain == "" {
				plain = callbackTestEvent
			}
			receiver := tc.receiver
			if receiver == "" {
				receiver = cfg.ReceiverID
			}
			enc := callbackTestEncrypted(t, plain, receiver, "1234567890123456")
			q := callbackTestQuery(enc)
			if tc.query != nil {
				tc.query(q)
			}
			_, err := VerifyAdminCallbackEvent(cfg, q, []byte(`<xml><Encrypt>`+enc+`</Encrypt></xml>`), now)
			require.Error(t, err)
			require.Equal(t, tc.status, CallbackErrorStatus(err))
			require.NotContains(t, err.Error(), "attacker@example.org")
		})
	}
}

func TestAdminCallbackForgedValidatedCannotRefresh(t *testing.T) {
	mockCallbackSettings(t)
	_, err := HandleAdminAuthorityCallback(t.Context(), fakeAdminAuthorityClient{}, AdminAuthorityCallback{Validated: true, CorpID: "corp-auth", AgentID: "1000002", Event: WeComChangeAppAdminEvent})
	require.ErrorIs(t, err, ErrWeComDenied)
}

func TestAdminCallbackRejectsAmbiguousXMLAndInvalidCrypto(t *testing.T) {
	cfg := callbackTestConfig()
	now := time.Unix(1780000000, 0)
	encrypted := callbackTestEncrypted(t, callbackTestEvent, cfg.ReceiverID, "1234567890123456")
	for _, body := range []string{`<xml><Encrypt>` + encrypted + `</Encrypt><Encrypt>` + encrypted + `</Encrypt></xml>`, `<!DOCTYPE xml [<!ENTITY x SYSTEM "file:///etc/passwd">]><xml><Encrypt>&x;</Encrypt></xml>`, `<xml><Encrypt>` + encrypted + `</Encrypt></xml><xml/>`, `<xml><Encrypt><nested/></Encrypt></xml>`} {
		_, err := VerifyAdminCallbackEvent(cfg, callbackTestQuery(encrypted), []byte(body), now)
		require.Equal(t, 400, CallbackErrorStatus(err))
	}
	key, err := base64.StdEncoding.DecodeString(cfg.AESKey + "=")
	require.NoError(t, err)
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	data, err := base64.StdEncoding.DecodeString(encrypted)
	require.NoError(t, err)
	cipher.NewCBCDecrypter(block, key[:16]).CryptBlocks(data, data)
	for _, mutation := range []func([]byte){func(b []byte) { b[len(b)-2] ^= 1 }, func(b []byte) { b[len(b)-1] = 0 }, func(b []byte) { binary.BigEndian.PutUint32(b[16:20], 0xffffffff) }} {
		broken := bytes.Clone(data)
		mutation(broken)
		cipher.NewCBCEncrypter(block, key[:16]).CryptBlocks(broken, broken)
		enc := base64.StdEncoding.EncodeToString(broken)
		_, err := VerifyAdminCallbackEvent(cfg, callbackTestQuery(enc), []byte(`<xml><Encrypt>`+enc+`</Encrypt></xml>`), now)
		require.Equal(t, 400, CallbackErrorStatus(err))
	}
	for _, enc := range []string{"not base64", base64.StdEncoding.EncodeToString([]byte("short ciphertext")), encrypted[:len(encrypted)-1]} {
		_, err := VerifyAdminCallbackEvent(cfg, callbackTestQuery(enc), []byte(`<xml><Encrypt>`+enc+`</Encrypt></xml>`), now)
		require.Equal(t, 400, CallbackErrorStatus(err))
	}
}

func TestAdminCallbackDisabledCannotRefreshVerifiedEvent(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	mockAuthoritySettings(t)
	enc := callbackTestEncrypted(t, callbackTestEvent, callbackTestConfig().ReceiverID, "1234567890123456")
	verified, err := VerifyAdminCallbackEvent(callbackTestConfig(), callbackTestQuery(enc), []byte(`<xml><Encrypt>`+enc+`</Encrypt></xml>`), time.Unix(1780000000, 0))
	require.NoError(t, err)
	_, err = HandleAdminAuthorityCallback(t.Context(), fakeAdminAuthorityClient{admins: []AppAdminInfo{{UserID: "new-admin", AuthType: 1}}}, verified)
	require.ErrorIs(t, err, ErrWeComDisabled)
}
