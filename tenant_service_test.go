package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeDomainAPI struct{}

func (fakeDomainAPI) AddDomain(context.Context, string, string) (string, error) {
	return "zone_test_42", nil
}
func (fakeDomainAPI) UpsertCNAME(context.Context, string, string, string) error { return nil }
func (fakeDomainAPI) VerifyDomain(context.Context, string) error                { return nil }
func (fakeDomainAPI) DeleteDomain(context.Context, string) error                { return nil }

type failingDomainAPI struct {
	upsertErr error
	verifyErr error
	deleteErr error
	deleted   []string
}

func (*failingDomainAPI) AddDomain(context.Context, string, string) (string, error) {
	return "zone_test_42", nil
}
func (f *failingDomainAPI) UpsertCNAME(context.Context, string, string, string) error {
	return f.upsertErr
}
func (f *failingDomainAPI) VerifyDomain(context.Context, string) error { return f.verifyErr }
func (f *failingDomainAPI) DeleteDomain(_ context.Context, domain string) error {
	f.deleted = append(f.deleted, domain)
	return f.deleteErr
}

func TestCreateTenantCleansUpDomainAfterLaterFailure(t *testing.T) {
	tests := []struct {
		name      string
		upsertErr error
		verifyErr error
		deleteErr error
	}{
		{name: "upsert failure", upsertErr: errors.New("upsert failed")},
		{name: "verification failure", verifyErr: errors.New("verification failed")},
		{name: "cleanup failure is reported", upsertErr: errors.New("upsert failed"), deleteErr: errors.New("delete failed")},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			api := &failingDomainAPI{upsertErr: test.upsertErr, verifyErr: test.verifyErr, deleteErr: test.deleteErr}
			service := NewTenantService(api, "secret")
			req := httptest.NewRequest(http.MethodPost, "/tenants", strings.NewReader(
				`{"tenant_id":"tenant_123","domain":"portal.acme.test","target":"edge.example.net"}`,
			))
			res := httptest.NewRecorder()

			service.Handler().ServeHTTP(res, req)

			if res.Code != http.StatusBadGateway {
				t.Fatalf("status = %d, want %d", res.Code, http.StatusBadGateway)
			}
			if len(api.deleted) != 1 || api.deleted[0] != "portal.acme.test" {
				t.Fatalf("deleted domains = %v, want [portal.acme.test]", api.deleted)
			}
			if test.deleteErr != nil && !strings.Contains(res.Body.String(), "cleanup failed: delete failed") {
				t.Fatalf("response %q does not report cleanup failure", res.Body.String())
			}
		})
	}
}

func TestVerificationEventActivatesMatchingTenant(t *testing.T) {
	const secret = "test-webhook-secret"
	tests := []struct {
		name       string
		body       string
		signature  func([]byte) string
		wantStatus int
		wantTenant string
	}{
		{
			name:       "matching verified domain activates tenant",
			body:       `{"type":"dns.domain.verified","data":{"domain":"portal.acme.test"}}`,
			signature:  func(body []byte) string { return sign(body, secret) },
			wantStatus: http.StatusNoContent,
			wantTenant: "active",
		},
		{
			name:       "another domain leaves tenant pending",
			body:       `{"type":"dns.domain.verified","data":{"domain":"other.test"}}`,
			signature:  func(body []byte) string { return sign(body, secret) },
			wantStatus: http.StatusNoContent,
			wantTenant: "pending_verification",
		},
		{
			name:       "unsigned event is rejected",
			body:       `{"type":"dns.domain.verified","data":{"domain":"portal.acme.test"}}`,
			signature:  func([]byte) string { return "" },
			wantStatus: http.StatusUnauthorized,
			wantTenant: "pending_verification",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := NewTenantService(fakeDomainAPI{}, secret)
			service.tenants["tenant_123"] = Tenant{
				ID: "tenant_123", Domain: "portal.acme.test", ZoneID: "zone_test_42", Status: "pending_verification",
			}
			body := []byte(test.body)
			req := httptest.NewRequest(http.MethodPost, "/webhooks/infrai", bytes.NewReader(body))
			req.Header.Set("X-Infrai-Signature", test.signature(body))
			res := httptest.NewRecorder()

			service.Handler().ServeHTTP(res, req)

			if res.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d", res.Code, test.wantStatus)
			}
			if got := service.tenants["tenant_123"].Status; got != test.wantTenant {
				t.Fatalf("tenant status = %q, want %q", got, test.wantTenant)
			}
		})
	}
}

func sign(body []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}
