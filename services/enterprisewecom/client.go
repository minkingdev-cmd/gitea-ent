// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterprisewecom

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"gitea.dev/modules/json"
	"gitea.dev/modules/setting"
)

var (
	ErrWeComDenied               = errors.New("wecom login denied")
	ErrWeComDisabled             = errors.New("enterprise wecom is disabled")
	ErrWeComUnavailable          = errors.New("wecom service unavailable")
	ErrWeComAuthorityUnsupported = errors.New("wecom administrator authority source is unsupported")
)

type APIError struct {
	Operation  string
	StatusCode int
	ErrorCode  int
}

func (e *APIError) Error() string {
	switch {
	case e.ErrorCode != 0:
		return fmt.Sprintf("wecom %s failed with error code %d", e.Operation, e.ErrorCode)
	case e.StatusCode != 0:
		return fmt.Sprintf("wecom %s failed with HTTP status %d", e.Operation, e.StatusCode)
	default:
		return fmt.Sprintf("wecom %s failed", e.Operation)
	}
}

func (e *APIError) Unwrap() error {
	if e.ErrorCode != 0 {
		return ErrWeComDenied
	}
	return ErrWeComUnavailable
}

type Config struct {
	CorpID            string
	CorpSecret        string
	AgentID           string
	SuiteAccessToken  string
	SuperAdminTagName string
	APIBaseURL        string
	HTTPTimeout       time.Duration
	HTTPClient        *http.Client
}

type Client struct {
	cfg Config

	tokenMu     sync.Mutex
	accessToken string
	expiresAt   time.Time
}

type Member struct {
	CorpID   string
	AgentID  string
	UserID   string
	DeviceID string
	Name     string
	Email    string
}

type AppAdminInfo struct {
	UserID     string
	OpenUserID string
	AuthType   int
}

func NewClient(cfg Config) *Client {
	cfg.APIBaseURL = strings.TrimRight(cfg.APIBaseURL, "/")
	if cfg.APIBaseURL == "" {
		cfg.APIBaseURL = "https://qyapi.weixin.qq.com"
	}
	if cfg.HTTPTimeout <= 0 {
		cfg.HTTPTimeout = 15 * time.Second
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: cfg.HTTPTimeout}
	}
	return &Client{cfg: cfg}
}

func NewClientFromSettings() *Client {
	cfg := setting.EnterpriseWeCom
	return NewClient(Config{
		CorpID:            cfg.CorpID,
		CorpSecret:        cfg.CorpSecret,
		AgentID:           cfg.AgentID,
		SuperAdminTagName: cfg.SuperAdminTagName,
		APIBaseURL:        cfg.APIBaseURL,
		HTTPTimeout:       cfg.HTTPTimeout,
	})
}

func (c *Client) ResolveOAuthUser(ctx context.Context, code string) (*Member, error) {
	token, err := c.GetAccessToken(ctx)
	if err != nil {
		return nil, err
	}
	userInfo, err := c.GetUserInfo(ctx, token.AccessToken, code)
	if err != nil {
		return nil, err
	}
	if userInfo.UserID == "" {
		return nil, fmt.Errorf("%w: missing userid", ErrWeComDenied)
	}
	return &Member{
		CorpID:   c.cfg.CorpID,
		AgentID:  c.cfg.AgentID,
		UserID:   userInfo.UserID,
		DeviceID: userInfo.DeviceID,
	}, nil
}

type AccessToken struct {
	AccessToken string
	ExpiresAt   time.Time
}

func (c *Client) GetAccessToken(ctx context.Context) (*AccessToken, error) {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()

	now := time.Now()
	if c.accessToken != "" && now.Before(c.expiresAt.Add(-2*time.Minute)) {
		return &AccessToken{AccessToken: c.accessToken, ExpiresAt: c.expiresAt}, nil
	}

	values := url.Values{}
	values.Set("corpid", c.cfg.CorpID)
	values.Set("corpsecret", c.cfg.CorpSecret)
	var resp struct {
		weComError
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := c.getJSON(ctx, "get access token", "/cgi-bin/gettoken", values, &resp); err != nil {
		return nil, err
	}
	if err := resp.Err("get access token"); err != nil {
		return nil, err
	}
	if resp.AccessToken == "" {
		return nil, fmt.Errorf("%w: missing access token", ErrWeComDenied)
	}

	c.accessToken = resp.AccessToken
	c.expiresAt = now.Add(time.Duration(resp.ExpiresIn) * time.Second)
	return &AccessToken{AccessToken: c.accessToken, ExpiresAt: c.expiresAt}, nil
}

type UserInfo struct {
	UserID   string
	DeviceID string
}

func (c *Client) GetUserInfo(ctx context.Context, accessToken, code string) (*UserInfo, error) {
	values := url.Values{}
	values.Set("access_token", accessToken)
	values.Set("code", code)
	var resp struct {
		weComError
		UserID   string `json:"userid"`
		DeviceID string `json:"deviceid"`
	}
	if err := c.getJSON(ctx, "get user identity", "/cgi-bin/auth/getuserinfo", values, &resp); err != nil {
		return nil, err
	}
	if err := resp.Err("get user identity"); err != nil {
		return nil, err
	}
	return &UserInfo{UserID: resp.UserID, DeviceID: resp.DeviceID}, nil
}

type weComError struct {
	ErrCode *int   `json:"errcode"`
	ErrMsg  string `json:"errmsg"`
}

func (e weComError) Err(operation string) error {
	if e.ErrCode == nil {
		return fmt.Errorf("%w: %s response is missing error code", ErrWeComUnavailable, operation)
	}
	if *e.ErrCode == 0 {
		return nil
	}
	return &APIError{Operation: operation, ErrorCode: *e.ErrCode}
}

func (c *Client) getJSON(ctx context.Context, operation, path string, values url.Values, out any) error {
	endpoint := c.cfg.APIBaseURL + path + "?" + values.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("%w: %s request is invalid", ErrWeComUnavailable, operation)
	}
	resp, err := c.cfg.HTTPClient.Do(req)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return context.Canceled
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("%w: %s timed out", ErrWeComUnavailable, operation)
		}
		return fmt.Errorf("%w: %s request failed", ErrWeComUnavailable, operation)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return &APIError{Operation: operation, StatusCode: resp.StatusCode}
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("%w: %s response is invalid", ErrWeComUnavailable, operation)
	}
	return nil
}

func (c *Client) postJSON(ctx context.Context, operation, path string, values url.Values, body, out any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("%w: %s request is invalid", ErrWeComUnavailable, operation)
	}
	endpoint := c.cfg.APIBaseURL + path + "?" + values.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("%w: %s request is invalid", ErrWeComUnavailable, operation)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.cfg.HTTPClient.Do(req)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return context.Canceled
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("%w: %s timed out", ErrWeComUnavailable, operation)
		}
		return fmt.Errorf("%w: %s request failed", ErrWeComUnavailable, operation)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return &APIError{Operation: operation, StatusCode: resp.StatusCode}
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("%w: %s response is invalid", ErrWeComUnavailable, operation)
	}
	return nil
}

func (c *Client) ListAppAdmins(ctx context.Context) ([]AppAdminInfo, error) {
	if c.cfg.SuiteAccessToken == "" {
		return c.listTaggedManagementAdmins(ctx)
	}
	agentID := any(c.cfg.AgentID)
	if parsedAgentID, err := strconv.ParseInt(c.cfg.AgentID, 10, 64); err == nil {
		agentID = parsedAgentID
	}
	values := url.Values{}
	values.Set("suite_access_token", c.cfg.SuiteAccessToken)
	var resp struct {
		weComError
		Admins []struct {
			UserID     string `json:"userid"`
			OpenUserID string `json:"open_userid"`
			AuthType   *int   `json:"auth_type"`
		} `json:"admin"`
	}
	if err := c.postJSON(ctx, "list app administrators", "/cgi-bin/service/get_admin_list", values, map[string]any{
		"auth_corpid": c.cfg.CorpID,
		"agentid":     agentID,
	}, &resp); err != nil {
		return nil, err
	}
	if err := resp.Err("list app administrators"); err != nil {
		return nil, err
	}
	if resp.Admins == nil {
		return nil, governanceError("authority", "incomplete_authority_source")
	}
	admins := make([]AppAdminInfo, 0, len(resp.Admins))
	for _, admin := range resp.Admins {
		if admin.AuthType == nil {
			return nil, governanceError("authority", "incomplete_authority_source")
		}
		admins = append(admins, AppAdminInfo{UserID: admin.UserID, OpenUserID: admin.OpenUserID, AuthType: *admin.AuthType})
	}
	return admins, nil
}

func (c *Client) listTaggedManagementAdmins(ctx context.Context) ([]AppAdminInfo, error) {
	tagName := strings.TrimSpace(c.cfg.SuperAdminTagName)
	if tagName == "" {
		return nil, ErrWeComAuthorityUnsupported
	}
	tags, err := c.ListTags(ctx)
	if err != nil {
		return nil, err
	}
	var matching []TagInfo
	for _, tag := range tags {
		if strings.TrimSpace(tag.Name) == tagName {
			matching = append(matching, tag)
		}
	}
	if len(matching) == 0 {
		return nil, governanceError("authority", "authority_source_missing")
	}
	if len(matching) != 1 {
		return nil, governanceError("authority", "authority_source_ambiguous")
	}
	for _, tag := range matching {
		if strings.TrimSpace(tag.Name) != tagName {
			continue
		}
		userIDs, err := c.ListTagMembers(ctx, tag.ID)
		if err != nil {
			return nil, err
		}
		admins := make([]AppAdminInfo, 0, len(userIDs))
		seen := map[string]struct{}{}
		for _, userID := range userIDs {
			userID = strings.TrimSpace(userID)
			if userID == "" {
				return nil, governanceError("authority", "incomplete_authority_source")
			}
			if _, ok := seen[userID]; ok {
				continue
			}
			seen[userID] = struct{}{}
			admins = append(admins, AppAdminInfo{UserID: userID, AuthType: 1})
		}
		return admins, nil
	}
	return []AppAdminInfo{}, nil
}

func (c *Client) ListDepartments(ctx context.Context) ([]DepartmentInfo, error) {
	token, err := c.GetAccessToken(ctx)
	if err != nil {
		return nil, err
	}
	values := url.Values{}
	values.Set("access_token", token.AccessToken)
	var resp struct {
		weComError
		Departments []struct {
			ID            int64    `json:"id"`
			ParentID      int64    `json:"parentid"`
			Name          string   `json:"name"`
			Order         int64    `json:"order"`
			LeaderUserIDs []string `json:"department_leader"`
		} `json:"department"`
	}
	if err := c.getJSON(ctx, "list departments", "/cgi-bin/department/list", values, &resp); err != nil {
		return nil, err
	}
	if err := resp.Err("list departments"); err != nil {
		return nil, err
	}
	if resp.Departments == nil {
		return nil, governanceError("directory", "incomplete_directory_source")
	}
	departments := make([]DepartmentInfo, 0, len(resp.Departments))
	for _, dept := range resp.Departments {
		departments = append(departments, DepartmentInfo{
			ID:            dept.ID,
			ParentID:      dept.ParentID,
			Name:          dept.Name,
			Order:         dept.Order,
			LeaderUserIDs: dept.LeaderUserIDs,
		})
	}
	return departments, nil
}

func (c *Client) GetDepartment(ctx context.Context, departmentID int64) (*DepartmentInfo, error) {
	token, err := c.GetAccessToken(ctx)
	if err != nil {
		return nil, err
	}
	values := url.Values{}
	values.Set("access_token", token.AccessToken)
	values.Set("id", strconv.FormatInt(departmentID, 10))
	var resp struct {
		weComError
		Department struct {
			ID            int64    `json:"id"`
			ParentID      int64    `json:"parentid"`
			Name          string   `json:"name"`
			Order         int64    `json:"order"`
			LeaderUserIDs []string `json:"department_leader"`
		} `json:"department"`
	}
	if err := c.getJSON(ctx, "get department", "/cgi-bin/department/get", values, &resp); err != nil {
		return nil, err
	}
	if err := resp.Err("get department"); err != nil {
		return nil, err
	}
	return &DepartmentInfo{
		ID:            resp.Department.ID,
		ParentID:      resp.Department.ParentID,
		Name:          resp.Department.Name,
		Order:         resp.Department.Order,
		LeaderUserIDs: resp.Department.LeaderUserIDs,
	}, nil
}

func (c *Client) ListMembers(ctx context.Context, departmentID int64) ([]MemberInfo, error) {
	token, err := c.GetAccessToken(ctx)
	if err != nil {
		return nil, err
	}
	values := url.Values{}
	values.Set("access_token", token.AccessToken)
	values.Set("department_id", strconv.FormatInt(departmentID, 10))
	values.Set("fetch_child", "0")
	var resp struct {
		weComError
		Users []struct {
			UserID         string  `json:"userid"`
			Name           string  `json:"name"`
			Email          string  `json:"email"`
			DepartmentIDs  []int64 `json:"department"`
			IsLeaderInDept []int   `json:"is_leader_in_dept"`
		} `json:"userlist"`
	}
	if err := c.getJSON(ctx, "list department members", "/cgi-bin/user/list", values, &resp); err != nil {
		return nil, err
	}
	if err := resp.Err("list department members"); err != nil {
		return nil, err
	}
	if resp.Users == nil {
		return nil, governanceError("directory", "incomplete_directory_source")
	}
	members := make([]MemberInfo, 0, len(resp.Users))
	for _, user := range resp.Users {
		members = append(members, MemberInfo{
			UserID:                user.UserID,
			Name:                  user.Name,
			Email:                 user.Email,
			DepartmentIDs:         user.DepartmentIDs,
			LeaderInDepartmentIDs: leaderDepartmentIDs(user.DepartmentIDs, user.IsLeaderInDept),
		})
	}
	return members, nil
}

func leaderDepartmentIDs(departmentIDs []int64, isLeaderInDept []int) []int64 {
	leaders := make([]int64, 0)
	for idx, departmentID := range departmentIDs {
		if idx < len(isLeaderInDept) && isLeaderInDept[idx] == 1 {
			leaders = append(leaders, departmentID)
		}
	}
	return leaders
}

func (c *Client) ListTags(ctx context.Context) ([]TagInfo, error) {
	token, err := c.GetAccessToken(ctx)
	if err != nil {
		return nil, err
	}
	values := url.Values{}
	values.Set("access_token", token.AccessToken)
	var resp struct {
		weComError
		Tags []struct {
			ID   int64  `json:"tagid"`
			Name string `json:"tagname"`
		} `json:"taglist"`
	}
	if err := c.getJSON(ctx, "list tags", "/cgi-bin/tag/list", values, &resp); err != nil {
		return nil, err
	}
	if err := resp.Err("list tags"); err != nil {
		return nil, err
	}
	if resp.Tags == nil {
		return nil, governanceError("directory", "incomplete_directory_source")
	}
	tags := make([]TagInfo, 0, len(resp.Tags))
	for _, tag := range resp.Tags {
		tags = append(tags, TagInfo{ID: tag.ID, Name: tag.Name})
	}
	return tags, nil
}

func (c *Client) ListTagMembers(ctx context.Context, tagID int64) ([]string, error) {
	token, err := c.GetAccessToken(ctx)
	if err != nil {
		return nil, err
	}
	values := url.Values{}
	values.Set("access_token", token.AccessToken)
	values.Set("tagid", strconv.FormatInt(tagID, 10))
	var resp struct {
		weComError
		Users []struct {
			UserID string `json:"userid"`
		} `json:"userlist"`
	}
	if err := c.getJSON(ctx, "list tag members", "/cgi-bin/tag/get", values, &resp); err != nil {
		return nil, err
	}
	if err := resp.Err("list tag members"); err != nil {
		return nil, err
	}
	if resp.Users == nil {
		return nil, governanceError("directory", "incomplete_directory_source")
	}
	userIDs := make([]string, 0, len(resp.Users))
	for _, user := range resp.Users {
		userIDs = append(userIDs, user.UserID)
	}
	return userIDs, nil
}
