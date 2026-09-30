// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterprisewecom

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"io"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"gitea.dev/modules/json"
)

const AdminCallbackBodyLimit = 1 << 20

type AdminCallbackConfig struct {
	Token      string
	AESKey     string
	ReceiverID string
	CorpID     string
	AgentID    string
}

type CallbackError struct {
	Status int
	Reason string
}

func (e *CallbackError) Error() string { return e.Reason }
func callbackError(status int, reason string) error {
	return &CallbackError{Status: status, Reason: reason}
}

func CallbackErrorStatus(err error) int {
	if safe, ok := errors.AsType[*CallbackError](err); ok {
		return safe.Status
	}
	return http.StatusServiceUnavailable
}

func callbackFields(data []byte) (map[string]string, error) {
	malformed := callbackError(http.StatusBadRequest, "callback_malformed")
	decoder := xml.NewDecoder(bytes.NewReader(data))
	fields := map[string]string{}
	depth := 0
	rootSeen := false
	closed := false
	name := ""
	var value strings.Builder
	for {
		tok, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, malformed
		}
		switch tok := tok.(type) {
		case xml.StartElement:
			if closed || tok.Name.Space != "" || len(tok.Attr) != 0 {
				return nil, malformed
			}
			depth++
			switch depth {
			case 1:
				if rootSeen || tok.Name.Local != "xml" {
					return nil, malformed
				}
				rootSeen = true
			case 2:
				name = tok.Name.Local
				if _, exists := fields[name]; exists {
					return nil, malformed
				}
				value.Reset()
			default:
				return nil, malformed
			}
		case xml.EndElement:
			if depth == 2 {
				fields[name] = strings.TrimSpace(value.String())
			}
			depth--
			if depth == 0 {
				closed = true
			}
		case xml.CharData:
			if depth == 2 {
				value.Write(tok)
			} else if len(bytes.TrimSpace(tok)) != 0 {
				return nil, malformed
			}
		case xml.Directive, xml.ProcInst:
			return nil, malformed
		}
	}
	if !rootSeen || !closed || depth != 0 {
		return nil, malformed
	}
	return fields, nil
}

func callbackTimestamp(value string, now time.Time) error {
	timestamp, err := strconv.ParseInt(value, 10, 64)
	if err != nil || timestamp <= 0 || strconv.FormatInt(timestamp, 10) != value {
		return callbackError(http.StatusBadRequest, "callback_malformed")
	}
	if timestamp < now.Unix()-600 || timestamp > now.Unix()+60 {
		return callbackError(http.StatusForbidden, "callback_timestamp_invalid")
	}
	return nil
}

func verifyCallbackPlain(cfg AdminCallbackConfig, q url.Values, encrypted string, now time.Time) ([]byte, error) {
	malformed := callbackError(http.StatusBadRequest, "callback_malformed")
	for _, values := range q {
		if len(values) != 1 {
			return nil, malformed
		}
	}
	for _, key := range []string{"timestamp", "nonce", "msg_signature"} {
		if len(q[key]) != 1 || q.Get(key) == "" {
			return nil, malformed
		}
	}
	if len(q.Get("nonce")) > 256 || len(encrypted) > AdminCallbackBodyLimit {
		return nil, malformed
	}
	if err := callbackTimestamp(q.Get("timestamp"), now); err != nil {
		return nil, err
	}
	signature, err := hex.DecodeString(q.Get("msg_signature"))
	if err != nil || len(signature) != sha1.Size {
		return nil, malformed
	}
	if cfg.Token == "" || cfg.ReceiverID == "" || len(cfg.AESKey) != 43 {
		return nil, callbackError(http.StatusServiceUnavailable, "callback_configuration_invalid")
	}
	key, err := base64.StdEncoding.DecodeString(cfg.AESKey + "=")
	if err != nil || len(key) != 32 {
		return nil, callbackError(http.StatusServiceUnavailable, "callback_configuration_invalid")
	}
	parts := []string{cfg.Token, q.Get("timestamp"), q.Get("nonce"), encrypted}
	slices.Sort(parts)
	expected := sha1.Sum([]byte(strings.Join(parts, "")))
	if subtle.ConstantTimeCompare(signature, expected[:]) != 1 {
		return nil, callbackError(http.StatusForbidden, "callback_signature_invalid")
	}
	if strings.ContainsAny(encrypted, "\r\n") {
		return nil, malformed
	}
	data, err := base64.StdEncoding.Strict().DecodeString(encrypted)
	if err != nil || len(data) == 0 || len(data)%32 != 0 {
		return nil, malformed
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, malformed
	}
	cipher.NewCBCDecrypter(block, key[:aes.BlockSize]).CryptBlocks(data, data)
	padding := int(data[len(data)-1])
	if padding < 1 || padding > 32 || padding > len(data) {
		return nil, malformed
	}
	for _, v := range data[len(data)-padding:] {
		if int(v) != padding {
			return nil, malformed
		}
	}
	data = data[:len(data)-padding]
	if len(data) < 20 {
		return nil, malformed
	}
	length := uint64(binary.BigEndian.Uint32(data[16:20]))
	if length > uint64(len(data)-20) {
		return nil, malformed
	}
	end := 20 + int(length)
	if subtle.ConstantTimeCompare(data[end:], []byte(cfg.ReceiverID)) != 1 {
		return nil, callbackError(http.StatusForbidden, "callback_receiver_mismatch")
	}
	return data[20:end], nil
}

func VerifyAdminCallbackChallenge(cfg AdminCallbackConfig, q url.Values, now time.Time) (string, error) {
	if len(q["echostr"]) != 1 || q.Get("echostr") == "" {
		return "", callbackError(http.StatusBadRequest, "callback_malformed")
	}
	plain, err := verifyCallbackPlain(cfg, q, q.Get("echostr"), now)
	return string(plain), err
}

func VerifyAdminCallbackEvent(cfg AdminCallbackConfig, q url.Values, body []byte, now time.Time) (AdminAuthorityCallback, error) {
	var callback AdminAuthorityCallback
	if len(body) > AdminCallbackBodyLimit {
		return callback, callbackError(http.StatusRequestEntityTooLarge, "callback_body_too_large")
	}
	fields, err := callbackFields(body)
	if err != nil {
		return callback, err
	}
	if fields["Encrypt"] == "" {
		return callback, callbackError(http.StatusBadRequest, "callback_malformed")
	}
	plain, err := verifyCallbackPlain(cfg, q, fields["Encrypt"], now)
	if err != nil {
		return callback, err
	}
	fields, err = callbackFields(plain)
	if err != nil {
		return callback, err
	}
	if cfg.CorpID == "" || cfg.AgentID == "" || fields["AuthCorpId"] != cfg.CorpID || fields["AgentID"] != cfg.AgentID {
		return callback, callbackError(http.StatusForbidden, "callback_scope_mismatch")
	}
	if fields["InfoType"] != WeComChangeAppAdminEvent {
		return callback, callbackError(http.StatusBadRequest, "callback_event_unsupported")
	}
	if fields["TimeStamp"] == "" {
		return callback, callbackError(http.StatusForbidden, "callback_timestamp_invalid")
	}
	if err = callbackTimestamp(fields["TimeStamp"], now); err != nil {
		return callback, err
	}
	type canonicalField struct {
		Name  string
		Value string
	}
	normalized := make([]canonicalField, 0, len(fields))
	for _, name := range slices.Sorted(maps.Keys(fields)) {
		normalized = append(normalized, canonicalField{Name: name, Value: fields[name]})
	}
	canonical, _ := json.Marshal(normalized)
	digest := sha256.Sum256(canonical)
	return AdminAuthorityCallback{CorpID: cfg.CorpID, AgentID: cfg.AgentID, InfoType: fields["InfoType"], Event: fields["InfoType"], verified: true, dedupKey: hex.EncodeToString(digest[:])}, nil
}
