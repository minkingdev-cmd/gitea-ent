// Copyright 2025 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package context

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"gitea.dev/modules/log"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testAccessLoggerMock struct {
	logs []string
}

func (t *testAccessLoggerMock) Log(skip int, event *log.Event, format string, v ...any) {
	t.logs = append(t.logs, fmt.Sprintf(format, v...))
}

func (t *testAccessLoggerMock) GetLevel() log.Level {
	return log.INFO
}

type testAccessLoggerResponseWriterMock struct{}

func (t testAccessLoggerResponseWriterMock) Header() http.Header {
	return nil
}

func (t testAccessLoggerResponseWriterMock) Before(f func(ResponseWriter)) {}

func (t testAccessLoggerResponseWriterMock) WriteHeader(statusCode int) {}

func (t testAccessLoggerResponseWriterMock) Write(bytes []byte) (int, error) {
	return 0, nil
}

func (t testAccessLoggerResponseWriterMock) Flush() {}

func (t testAccessLoggerResponseWriterMock) WrittenStatus() int {
	return http.StatusOK
}

func (t testAccessLoggerResponseWriterMock) WrittenSize() int {
	return 123123
}

func TestAccessLogger(t *testing.T) {
	setting.Log.AccessLogTemplate = `{{.Ctx.RemoteHost}} - {{.Identity}} {{.Start.Format "[02/Jan/2006:15:04:05 -0700]" }} "{{.Ctx.Req.Method}} {{.Ctx.Req.URL.RequestURI}} {{.Ctx.Req.Proto}}" {{.ResponseWriter.Status}} {{.ResponseWriter.Size}} "{{.Ctx.Req.Referer}}" "{{.Ctx.Req.UserAgent}}"`
	recorder := newAccessLogRecorder()
	mockLogger := &testAccessLoggerMock{}
	recorder.logger = mockLogger
	req := &http.Request{
		RemoteAddr: "remote-addr",
		Method:     http.MethodGet,
		Proto:      "https",
		URL:        &url.URL{Path: "/path"},
	}
	req.Header = http.Header{}
	req.Header.Add("Referer", "referer")
	req.Header.Add("User-Agent", "user-agent")
	recorder.record(time.Date(2000, 1, 2, 3, 4, 5, 0, time.UTC), &testAccessLoggerResponseWriterMock{}, req)
	assert.Equal(t, []string{`remote-addr - - [02/Jan/2000:03:04:05 +0000] "GET /path https" 200 123123 "referer" "user-agent"`}, mockLogger.logs)
}

func TestAccessLoggerRequestID(t *testing.T) {
	assert.False(t, isSafeRequestID("\x00"))
	assert.True(t, isSafeRequestID("a b-c"))
}

func TestAccessLoggerRedactsAdministratorCallbackRequest(t *testing.T) {
	for _, path := range []string{"/enterprise/wecom/callback/admin-authority", "/gitea/enterprise/wecom/callback/admin-authority"} {
		t.Run(path, func(t *testing.T) {
			defer test.MockVariableValue(&setting.Log.AccessLogTemplate, `{{.Ctx.Req.RequestURI}} {{.Ctx.Req.URL.String}} {{.Ctx.Req.Header}} {{.Ctx.Req.Form}} {{.Ctx.Req.Body}} {{.RequestID}}`)()
			defer test.MockVariableValue(&setting.Log.RequestIDHeaders, []string{"X-Request-ID"})()
			recorder := newAccessLogRecorder()
			logger := new(testAccessLoggerMock)
			recorder.logger = logger
			req := httptest.NewRequest(http.MethodPost, path+"?echostr=private-ciphertext&msg_signature=private-signature", strings.NewReader("private-body"))
			req.Header.Set("Referer", "https://example.invalid/?private-ciphertext")
			req.Header.Set("X-Request-ID", "private-request-id")
			req.Form = url.Values{"private-form": {"private-content"}}
			recorder.record(time.Now(), &testAccessLoggerResponseWriterMock{}, req)
			require.Len(t, logger.logs, 1)
			require.Contains(t, logger.logs[0], path)
			require.NotContains(t, logger.logs[0], "private-")
			require.Contains(t, req.URL.RawQuery, "private-ciphertext")
			require.Equal(t, "private-request-id", req.Header.Get("X-Request-ID"))
		})
	}
}
