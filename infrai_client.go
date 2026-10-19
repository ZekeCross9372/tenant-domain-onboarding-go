package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type APIError struct {
	Code       string
	Message    string
	HTTPStatus int
}

func (e *APIError) Error() string {
	if e.Code == "" {
		return e.Message
	}
	return e.Code + ": " + e.Message
}

type envelope struct {
	OK       bool            `json:"ok"`
	Data     json.RawMessage `json:"data"`
	Error    *apiErrorBody   `json:"error"`
	Metadata json.RawMessage `json:"metadata"`
}

type apiErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type InfraiClient struct {
	BaseURL string
	APIKey  string
	HTTP    *http.Client
	Sleep   func(context.Context, time.Duration) error
}

func NewInfraiClient(baseURL, apiKey string) *InfraiClient {
	return &InfraiClient{
		BaseURL: strings.TrimRight(baseURL, "/"),
		APIKey:  apiKey,
		HTTP:    &http.Client{Timeout: 10 * time.Second},
		Sleep: func(ctx context.Context, d time.Duration) error {
			timer := time.NewTimer(d)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
				return nil
			}
		},
	}
}

func (c *InfraiClient) AddDomain(ctx context.Context, domain, tenantID string) (string, error) {
	var result struct {
		ZoneID string `json:"zone_id"`
	}
	err := c.call(ctx, http.MethodPost, "/v1/dns/domain/add", map[string]any{
		"domain": domain,
		"metadata": map[string]string{
			"tenant_id":     tenantID,
			"onboarding_id": tenantID + ":" + domain,
		},
	}, &result)
	if err == nil && result.ZoneID == "" {
		return "", errors.New("domain response did not include zone_id")
	}
	return result.ZoneID, err
}

func (c *InfraiClient) UpsertCNAME(ctx context.Context, zoneID, name, target string) error {
	return c.call(ctx, http.MethodPut, "/v1/dns/record/upsert", map[string]any{
		"zone_id":     zoneID,
		"record_type": "CNAME",
		"name":        name,
		"content":     target,
		"ttl":         300,
		"proxied":     true,
	}, nil)
}

func (c *InfraiClient) VerifyDomain(ctx context.Context, domain string) error {
	return c.call(ctx, http.MethodPost, "/v1/dns/domain/verify", map[string]string{"domain": domain}, nil)
}

func (c *InfraiClient) DeleteDomain(ctx context.Context, domain string) error {
	return c.call(ctx, http.MethodDelete, "/v1/dns/domain/delete", map[string]string{"domain": domain}, nil)
}

func (c *InfraiClient) call(ctx context.Context, method, path string, payload, out any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode request: %w", err)
	}

	for attempt := 0; attempt < 4; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("build request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
		req.Header.Set("Content-Type", "application/json")

		res, err := c.HTTP.Do(req)
		if err != nil {
			return fmt.Errorf("send request: %w", err)
		}
		responseBody, readErr := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		res.Body.Close()
		if readErr != nil {
			return fmt.Errorf("read response: %w", readErr)
		}

		var env envelope
		if err := json.Unmarshal(responseBody, &env); err != nil {
			return fmt.Errorf("decode response envelope: %w", err)
		}
		if res.StatusCode == http.StatusTooManyRequests && attempt < 3 {
			delay := retryDelay(res.Header.Get("Retry-After"), attempt)
			if err := c.Sleep(ctx, delay); err != nil {
				return err
			}
			continue
		}
		if !env.OK {
			apiErr := &APIError{HTTPStatus: res.StatusCode, Message: "request rejected"}
			if env.Error != nil {
				apiErr.Code = env.Error.Code
				apiErr.Message = env.Error.Message
			}
			return apiErr
		}
		if res.StatusCode >= 500 {
			return fmt.Errorf("Infrai returned HTTP %d", res.StatusCode)
		}
		if out != nil && len(env.Data) > 0 && string(env.Data) != "null" {
			if err := json.Unmarshal(env.Data, out); err != nil {
				return fmt.Errorf("decode response data: %w", err)
			}
		}
		return nil
	}
	return errors.New("retry attempts exhausted")
}

func retryDelay(value string, attempt int) time.Duration {
	if seconds, err := strconv.Atoi(value); err == nil && seconds >= 0 {
		return time.Duration(seconds) * time.Second
	}
	return time.Duration(1<<attempt) * 250 * time.Millisecond
}
