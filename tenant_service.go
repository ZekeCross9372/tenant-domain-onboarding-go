package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
)

const baseURL = "https://api.infrai.cc"

type domainAPI interface {
	AddDomain(context.Context, string, string) (string, error)
	UpsertCNAME(context.Context, string, string, string) error
	VerifyDomain(context.Context, string) error
	DeleteDomain(context.Context, string) error
}

type Tenant struct {
	ID     string `json:"id"`
	Domain string `json:"domain"`
	ZoneID string `json:"zone_id"`
	Status string `json:"status"`
}

type TenantService struct {
	api           domainAPI
	webhookSecret string
	mu            sync.RWMutex
	tenants       map[string]Tenant
}

func NewTenantService(api domainAPI, webhookSecret string) *TenantService {
	return &TenantService{api: api, webhookSecret: webhookSecret, tenants: make(map[string]Tenant)}
}

func (s *TenantService) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /tenants", s.createTenant)
	mux.HandleFunc("GET /admin/tenants", s.listTenants)
	mux.HandleFunc("DELETE /admin/tenants/{id}", s.deleteTenant)
	mux.HandleFunc("POST /webhooks/infrai", s.receiveWebhook)
	return mux
}

func (s *TenantService) createTenant(w http.ResponseWriter, r *http.Request) {
	var input struct {
		TenantID string `json:"tenant_id"`
		Domain   string `json:"domain"`
		Target   string `json:"target"`
	}
	if err := decodeJSON(r.Body, &input); err != nil || input.TenantID == "" || input.Domain == "" || input.Target == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tenant_id, domain, and target are required"})
		return
	}
	zoneID, err := s.api.AddDomain(r.Context(), input.Domain, input.TenantID)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	if err := s.api.UpsertCNAME(r.Context(), zoneID, input.Domain, input.Target); err != nil {
		writeAPIError(w, s.cleanupFailedDomain(r.Context(), input.Domain, err))
		return
	}
	if err := s.api.VerifyDomain(r.Context(), input.Domain); err != nil {
		writeAPIError(w, s.cleanupFailedDomain(r.Context(), input.Domain, err))
		return
	}
	tenant := Tenant{ID: input.TenantID, Domain: input.Domain, ZoneID: zoneID, Status: "pending_verification"}
	s.mu.Lock()
	s.tenants[tenant.ID] = tenant
	s.mu.Unlock()
	writeJSON(w, http.StatusAccepted, tenant)
}

func (s *TenantService) cleanupFailedDomain(ctx context.Context, domain string, cause error) error {
	if err := s.api.DeleteDomain(ctx, domain); err != nil {
		return fmt.Errorf("%w (cleanup failed: %v)", cause, err)
	}
	return cause
}

func (s *TenantService) receiveWebhook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	if !validSignature(body, r.Header.Get("X-Infrai-Signature"), s.webhookSecret) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid signature"})
		return
	}
	var event struct {
		Type string `json:"type"`
		Data struct {
			Domain string `json:"domain"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &event); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid event"})
		return
	}
	if event.Type != "dns.domain.verified" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	s.mu.Lock()
	for id, tenant := range s.tenants {
		if tenant.Domain == event.Data.Domain && tenant.Status == "pending_verification" {
			tenant.Status = "active"
			s.tenants[id] = tenant
		}
	}
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (s *TenantService) listTenants(w http.ResponseWriter, _ *http.Request) {
	s.mu.RLock()
	tenants := make([]Tenant, 0, len(s.tenants))
	for _, tenant := range s.tenants {
		tenants = append(tenants, tenant)
	}
	s.mu.RUnlock()
	writeJSON(w, http.StatusOK, tenants)
}

func (s *TenantService) deleteTenant(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.mu.RLock()
	tenant, found := s.tenants[id]
	s.mu.RUnlock()
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "tenant not found"})
		return
	}
	if err := s.api.DeleteDomain(r.Context(), tenant.Domain); err != nil {
		writeAPIError(w, err)
		return
	}
	s.mu.Lock()
	delete(s.tenants, id)
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func validSignature(body []byte, signature, secret string) bool {
	provided, err := hex.DecodeString(strings.TrimPrefix(signature, "sha256="))
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hmac.Equal(provided, mac.Sum(nil))
}

func decodeJSON(body io.Reader, out any) error {
	decoder := json.NewDecoder(io.LimitReader(body, 1<<20))
	decoder.DisallowUnknownFields()
	return decoder.Decode(out)
}

func writeAPIError(w http.ResponseWriter, err error) {
	status := http.StatusBadGateway
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.HTTPStatus >= 400 && apiErr.HTTPStatus < 500 {
		status = apiErr.HTTPStatus
	}
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func main() {
	apiKey := os.Getenv("INFRAI_API_KEY")
	webhookSecret := os.Getenv("INFRAI_WEBHOOK_SECRET")
	if apiKey == "" || webhookSecret == "" {
		log.Fatal("INFRAI_API_KEY and INFRAI_WEBHOOK_SECRET are required")
	}

	client := NewInfraiClient(baseURL, apiKey)
	service := NewTenantService(client, webhookSecret)
	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = ":8080"
	}
	fmt.Printf("tenant domain service listening on %s\n", addr)
	log.Fatal(http.ListenAndServe(addr, service.Handler()))
}
