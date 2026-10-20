package main

// host_field_roundtrip_test.go locks the AuthData round-trip contract that the
// CPA management UI depends on: editor-owned fields (prefix / weight /
// priority / proxy_url / headers / unknown future keys) must survive
// auth.parse, auth.refresh, lifecycle rewrites and legacy adoption.
//
// Regression: saving "prefix" in the panel used to drop "weight", and saving
// "weight" then dropped "prefix" again, because StorageJSON only carried the
// typed auth/account objects while the host kept the other field in its
// runtime-only attributes.

import (
	"encoding/json"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

const hostPanelDoc = `{
  "type": "qoder",
  "provider": "qoder",
  "auth_kind": "oauth",
  "disabled": false,
  "note": "keep note",
  "prefix": "Qodermo",
  "weight": 4,
  "priority": 7,
  "proxy_url": "direct",
  "request_retry": 5,
  "headers": {"X-Team": "blue"},
  "custom": {"future_host_field": true},
  "unknown_future_field": {"must": "survive"},
  "auth": {"accessToken": "dt-live", "refreshToken": "drt-live", "personalToken": "pt-live", "expiresAt": 1700000000, "domain": "qoder.com.cn", "region": "cn", "providerFlag": "keep"},
  "account": {"uid": "u-1", "enterpriseId": "e-1", "nickname": "n-1", "accountFlag": "keep"}
}`

func decodeDoc(t *testing.T, raw []byte) map[string]json.RawMessage {
	t.Helper()
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode: %v (raw=%s)", err, raw)
	}
	return doc
}

func assertJSONEqual(t *testing.T, doc map[string]json.RawMessage, key, want string) {
	t.Helper()
	got, ok := doc[key]
	if !ok {
		t.Fatalf("missing key %q in %v", key, doc)
	}
	var g, w any
	if err := json.Unmarshal(got, &g); err != nil {
		t.Fatalf("decode %q: %v", key, err)
	}
	if err := json.Unmarshal([]byte(want), &w); err != nil {
		t.Fatalf("decode want %q: %v", key, err)
	}
	gb, _ := json.Marshal(g)
	wb, _ := json.Marshal(w)
	if string(gb) != string(wb) {
		t.Fatalf("%s = %s, want %s", key, gb, wb)
	}
}

// --- auth.parse keeps every host-owned field in StorageJSON and Metadata ---

func TestParseAuthPreservesHostFields(t *testing.T) {
	resp, err := handleParseAuth(mustMarshal(t, pluginapi.AuthParseRequest{
		Provider: providerName,
		FileName: "qoder-cn-u-1.json",
		RawJSON:  []byte(hostPanelDoc),
	}))
	if err != nil {
		t.Fatal(err)
	}
	var env envelope
	if err := json.Unmarshal(resp, &env); err != nil || !env.OK {
		t.Fatalf("parse envelope: %v %s", err, resp)
	}
	var pr pluginapi.AuthParseResponse
	if err := json.Unmarshal(env.Result, &pr); err != nil {
		t.Fatal(err)
	}
	if !pr.Handled {
		t.Fatal("credential not handled")
	}

	doc := decodeDoc(t, pr.Auth.StorageJSON)
	for key, want := range map[string]string{
		"prefix":               `"Qodermo"`,
		"weight":               `4`,
		"priority":             `7`,
		"proxy_url":            `"direct"`,
		"request_retry":        `5`,
		"headers":              `{"X-Team":"blue"}`,
		"custom":              `{"future_host_field":true}`,
		"unknown_future_field": `{"must":"survive"}`,
	} {
		assertJSONEqual(t, doc, key, want)
	}
	authObj := decodeDoc(t, doc["auth"])
	assertJSONEqual(t, authObj, "providerFlag", `"keep"`)
	acctObj := decodeDoc(t, doc["account"])
	assertJSONEqual(t, acctObj, "accountFlag", `"keep"`)

	// Metadata is what CPA merges back into the runtime record.
	for key, want := range map[string]string{
		"prefix":    `"Qodermo"`,
		"weight":    `4`,
		"priority":  `7`,
		"proxy_url": `"direct"`,
		"note":      `"keep note"`,
		"custom":    `{"future_host_field":true}`,
	} {
		got, ok := pr.Auth.Metadata[key]
		if !ok {
			t.Fatalf("metadata missing %q: %v", key, pr.Auth.Metadata)
		}
		gb, _ := json.Marshal(got)
		if string(gb) != want {
			t.Fatalf("metadata[%s] = %s, want %s", key, gb, want)
		}
	}
	if pr.Auth.Prefix != "Qodermo" {
		t.Fatalf("AuthData.Prefix = %q", pr.Auth.Prefix)
	}
	if pr.Auth.ProxyURL != "direct" {
		t.Fatalf("AuthData.ProxyURL = %q", pr.Auth.ProxyURL)
	}
	// Provider credential fields must not leak into Metadata.
	for _, key := range []string{"auth", "account", "accessToken", "refreshToken", "personalToken", "uid"} {
		if _, ok := pr.Auth.Metadata[key]; ok {
			t.Fatalf("credential field %q leaked into Metadata", key)
		}
	}
}

// --- alternating UI saves: prefix then weight, each must keep the other ---

func TestAlternatingPrefixAndWeightSavesPreserveBoth(t *testing.T) {
	doc := []byte(hostPanelDoc)

	// Save 1: the panel sends only the changed field (prefix).
	sa, err := parseStored(doc)
	if err != nil {
		t.Fatal(err)
	}
	merged := storageJSONForAuth(sa)
	var patched map[string]any
	if err := json.Unmarshal(merged, &patched); err != nil {
		t.Fatal(err)
	}
	patched["prefix"] = "Qodermo2"
	doc = mustMarshal(t, patched)

	d := decodeDoc(t, doc)
	assertJSONEqual(t, d, "prefix", `"Qodermo2"`)
	assertJSONEqual(t, d, "weight", `4`)

	// Save 2: only weight changes.
	sa, err = parseStored(doc)
	if err != nil {
		t.Fatal(err)
	}
	merged = storageJSONForAuth(sa)
	if err := json.Unmarshal(merged, &patched); err != nil {
		t.Fatal(err)
	}
	patched["weight"] = float64(9)
	doc = mustMarshal(t, patched)

	d = decodeDoc(t, doc)
	assertJSONEqual(t, d, "prefix", `"Qodermo2"`)
	assertJSONEqual(t, d, "weight", `9`)
	assertJSONEqual(t, d, "priority", `7`)
	assertJSONEqual(t, d, "headers", `{"X-Team":"blue"}`)
}

// --- auth.refresh must not wipe host fields or re-enable disabled accounts ---

func TestRefreshKeepsHostFieldsAndDisabledState(t *testing.T) {
	disabled := []byte(`{"type":"qoder","provider":"qoder","disabled":true,"note":"drained","prefix":"Qodermo","weight":4,"priority":7,"proxy_url":"direct","headers":{"X-Team":"blue"},"custom":{"keep":1},"auth":{"accessToken":"dt-old","refreshToken":"drt-old","expiresAt":1,"domain":"qoder.com.cn","region":"cn","providerFlag":"keep"},"account":{"uid":"u-1","accountFlag":"keep"}}`)

	sa, err := parseStored(disabled)
	if err != nil {
		t.Fatal(err)
	}
	sa.Auth.AccessToken = "dt-new"
	sa.Auth.RefreshToken = "drt-new"

	existing, isDisabled := authRefreshMetadata(pluginapi.AuthRefreshRequest{
		StorageJSON: disabled,
		Metadata:    map[string]any{"note": "host note"},
	})
	if !isDisabled {
		t.Fatal("disabled state lost before refresh return")
	}
	ad := toAuthDataForRefresh(sa, existing, isDisabled, disabled)

	if ad.FileName != "" || ad.ID != "" {
		t.Fatalf("refresh must leave FileName/ID empty, got %q/%q", ad.FileName, ad.ID)
	}
	if ad.Metadata["disabled"] != true {
		t.Fatalf("refresh re-enabled the credential: %v", ad.Metadata["disabled"])
	}
	if ad.Metadata["note"] != "host note" {
		t.Fatalf("host metadata did not win: %v", ad.Metadata["note"])
	}

	doc := decodeDoc(t, ad.StorageJSON)
	assertJSONEqual(t, doc, "disabled", `true`)
	assertJSONEqual(t, doc, "prefix", `"Qodermo"`)
	assertJSONEqual(t, doc, "weight", `4`)
	assertJSONEqual(t, doc, "priority", `7`)
	assertJSONEqual(t, doc, "proxy_url", `"direct"`)
	assertJSONEqual(t, doc, "custom", `{"keep":1}`)
	authObj := decodeDoc(t, doc["auth"])
	assertJSONEqual(t, authObj, "accessToken", `"dt-new"`)
	assertJSONEqual(t, authObj, "refreshToken", `"drt-new"`)
	assertJSONEqual(t, authObj, "providerFlag", `"keep"`)
	acctObj := decodeDoc(t, doc["account"])
	assertJSONEqual(t, acctObj, "accountFlag", `"keep"`)
}

// --- lifecycle rewrites operate on the live physical document ---

func TestLifecyclePreservingMergeKeepsHostFields(t *testing.T) {
	phys := &hostAuthPhysical{Name: "qoder-cn-u-1.json", JSON: []byte(hostPanelDoc)}
	stale := &storedAuth{
		Auth:    storedTokens{AccessToken: "stale-token", RefreshToken: "stale-rt", Domain: "qoder.com.cn", Region: regionCN},
		Account: storedAccount{UID: "u-1"},
	}
	raw, err := buildAuthFileJSONPreserving(phys, stale, true, "CN · 耗尽", nil)
	if err != nil {
		t.Fatal(err)
	}
	doc := decodeDoc(t, raw)
	assertJSONEqual(t, doc, "disabled", `true`)
	assertJSONEqual(t, doc, "note", `"CN · 耗尽"`)
	assertJSONEqual(t, doc, "prefix", `"Qodermo"`)
	assertJSONEqual(t, doc, "weight", `4`)
	assertJSONEqual(t, doc, "unknown_future_field", `{"must":"survive"}`)
	authObj := decodeDoc(t, doc["auth"])
	assertJSONEqual(t, authObj, "accessToken", `"dt-live"`)
	assertJSONEqual(t, authObj, "personalToken", `"pt-live"`)
}

// --- adoption rewrites classification only ---

func TestAdoptPreservingMergeKeepsFields(t *testing.T) {
	legacy := []byte(`{"type":"qoder-intl","provider":"qoder-intl","disabled":true,"note":"operator","prefix":"Qodermo","weight":4,"custom":{"keep":true},"auth":{"accessToken":"dt-i","refreshToken":"drt-i","domain":"qoder.com","region":"intl"},"account":{"uid":"u-i"}}`)
	sa, err := parseStored(legacy)
	if err != nil {
		t.Fatal(err)
	}
	sa.Auth.Region = regionIntl
	sa.Auth.Domain = domainForRegion(regionIntl)
	phys := &hostAuthPhysical{Name: "qoder-intl-u-i.json", JSON: legacy}
	raw, err := buildAuthFileJSONPreserving(phys, sa, true, "migrated from qoder-intl", nil)
	if err != nil {
		t.Fatal(err)
	}
	doc := decodeDoc(t, raw)
	assertJSONEqual(t, doc, "type", `"qoder"`)
	assertJSONEqual(t, doc, "provider", `"qoder"`)
	assertJSONEqual(t, doc, "auth_kind", `"oauth"`)
	assertJSONEqual(t, doc, "prefix", `"Qodermo"`)
	assertJSONEqual(t, doc, "weight", `4`)
	assertJSONEqual(t, doc, "custom", `{"keep":true}`)
	assertJSONEqual(t, doc, "disabled", `true`)
	authObj := decodeDoc(t, doc["auth"])
	assertJSONEqual(t, authObj, "region", `"intl"`)
	assertJSONEqual(t, authObj, "domain", `"qoder.com"`)
}

// --- flat legacy credentials keep their shape and region ---

func TestFlatCredentialKeepsShapeAndRegion(t *testing.T) {
	flat := []byte(`{"accessToken":"jt-1","refreshToken":"jrt-1","personalToken":"pt-1","domain":"qoder.com","region":"intl","uid":"u-f","prefix":"Qodermo","weight":4}`)
	sa, err := parseStored(flat)
	if err != nil {
		t.Fatal(err)
	}
	if sa.Auth.Region != regionIntl {
		t.Fatalf("flat intl region lost: %q", sa.Auth.Region)
	}
	merged := storageJSONForAuth(sa)
	doc := decodeDoc(t, merged)
	if _, nested := doc["auth"]; nested {
		t.Fatalf("flat credential became nested: %s", merged)
	}
	assertJSONEqual(t, doc, "personalToken", `"pt-1"`)
	assertJSONEqual(t, doc, "region", `"intl"`)
	assertJSONEqual(t, doc, "prefix", `"Qodermo"`)
	assertJSONEqual(t, doc, "weight", `4`)
	assertJSONEqual(t, doc, "type", `"qoder"`)
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
