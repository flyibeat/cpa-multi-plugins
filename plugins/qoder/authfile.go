// authfile.go owns every physical auth-file path the plugin touches: the
// qoderwork-<uid>.json naming rule, UID sanitization (path-traversal defense),
// path safety checks, and the read / write / delete helpers that talk to the
// host's auth store via host.auth.* RPC. Callers above (lifecycle reconcile)
// decide when to disable / re-enable / delete; this file decides how.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// authFileNameFor matches toAuthData naming: always qoderwork-<uid>.json when UID is known.
// Bare "qoderwork.json" is legacy single-account only (no UID).
var unsafeUIDChars = regexp.MustCompile(`[^a-zA-Z0-9_-]+`)

func sanitizeUIDForFileName(uid string) string {
	uid = strings.TrimSpace(uid)
	uid = unsafeUIDChars.ReplaceAllString(uid, "_")
	if uid == "" || uid == "." || uid == ".." {
		return ""
	}
	if len(uid) > 64 {
		uid = uid[:64]
	}
	return uid
}

func authFileNameFor(sa *storedAuth) string {
	if sa != nil {
		if uid := sanitizeUIDForFileName(sa.Account.UID); uid != "" {
			// Region-qualified canonical name (qoder-cn-<uid>.json /
			// qoder-intl-<uid>.json) — matches the legacy per-plugin
			// file names so adoption is rename-free.
			return "qoder-" + authRegion(sa) + "-" + uid + ".json"
		}
	}
	return authFileName
}

// isLegacyAuthName reports the historical single-file name that collides
// with multi-account qoderwork-<uid>.json for the same credential.

func isLegacyAuthName(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	return n == "qoder.json" || n == "qoder-cn.json" || n == "qoder-intl.json"
}

// resolveAuthFileTarget picks the canonical file name + path for save/delete.
// Prefer qoderwork-<uid>.json; if the host still points at legacy qoderwork.json
// for a UID-bearing account, rewrite to the uid name and schedule legacy removal.

func resolveAuthFileTarget(sa *storedAuth, phys *hostAuthPhysical) (name, path string, legacyPath string) {
	name = authFileNameFor(sa)
	if phys != nil {
		path = strings.TrimSpace(phys.Path)
		physName := strings.TrimSpace(phys.Name)
		if physName != "" && !isLegacyAuthName(physName) {
			// Already on multi-account name — keep host name (should match uid form).
			name = physName
		}
		if isLegacyAuthName(physName) || isLegacyAuthName(filepath.Base(path)) {
			if sa != nil && strings.TrimSpace(sa.Account.UID) != "" {
				// Migrate: write canonical, delete legacy path after save.
				legacyPath = path
				if isLegacyAuthName(filepath.Base(path)) {
					// path stays legacy until we write canonical beside it
				}
				// After persist to name, remove legacyPath if different.
			}
		}
	}
	return name, path, legacyPath
}

// hostAuthPersist saves via host API only. Dual-writing the physical path after
// a successful host.auth.save is redundant (host already WriteFile) and can
// re-fire the watcher → extra re-parse / transient dual registration risk.

type hostAuthPhysical struct {
	AuthIndex string
	Name      string
	Path      string
	JSON      []byte
	Disabled  bool
}

// hostAuthGetPhysicalFn / hostAuthPersistMigrateFn are indirection points so
// tests can exercise note-writing paths without a live host RPC bridge. Both
// default to the real host calls below.
var (
	hostAuthGetPhysicalFn    = hostAuthGetPhysical
	hostAuthPersistMigrateFn = hostAuthPersistMigrate
)

func hostAuthGetPhysical(authIndex string) (*hostAuthPhysical, error) {
	body, _ := json.Marshal(map[string]string{"auth_index": authIndex})
	raw, err := hostCall(pluginabi.MethodHostAuthGet, body)
	if err != nil {
		return nil, err
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil || !env.OK {
		// Issue #22: a bare "bad envelope" made startup adopt failures
		// undiagnosable — surface the host's error message (truncated,
		// envelope payloads carry no credentials).
		msg := "bad envelope"
		if env.Error != nil && strings.TrimSpace(env.Error.Message) != "" {
			msg = "bad envelope: " + truncateRedacted(env.Error.Message, 160)
		}
		return nil, fmt.Errorf("host.auth.get: %s", msg)
	}
	var resp rpcHostAuthGetResponse
	if err := json.Unmarshal(env.Result, &resp); err != nil {
		return nil, err
	}
	return &hostAuthPhysical{
		AuthIndex: resp.AuthIndex,
		Name:      resp.Name,
		Path:      resp.Path,
		JSON:      resp.JSON,
		Disabled:  parseDisabledFromAuthJSON(resp.JSON),
	}, nil
}

// hostAuthSaveJSON persists credential JSON via host.auth.save.

func hostAuthPersist(name, path string, raw []byte) error {
	_ = path // reserved for callers that still pass physical path for migrate logic
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("empty auth file name")
	}
	return hostAuthSaveJSON(name, raw)
}

// hostAuthPersistMigrate is like hostAuthPersist but also removes a legacy path
// when the canonical name differs (qoderwork.json → qoderwork-<uid>.json).

func hostAuthPersistMigrate(name, path, legacyPath string, raw []byte) error {
	if err := hostAuthPersist(name, path, raw); err != nil {
		return err
	}
	// If path was legacy and name is canonical, also write canonical path next to it.
	if legacyPath != "" && !strings.EqualFold(filepath.Base(legacyPath), name) {
		// host.auth.save already wrote name under auth dir; drop legacy file.
		// A-36: use deleteAuthFileInDir (abs path + dir confine) for consistency.
		if isLegacyAuthName(filepath.Base(legacyPath)) {
			_ = deleteAuthFileInDir(legacyPath, filepath.Dir(legacyPath))
		}
	}
	// If path points at legacy but name is uid form, do not dual-write path (would keep legacy alive).
	return nil
}

// buildAuthFileJSON produces host-save payload: nested storage + top-level metadata.
// extra merges additional top-level keys (optional).

func hostAuthSaveJSON(name string, raw []byte) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("empty auth file name")
	}
	// Every physical write carries the OAuth attribution and keeps foreign
	// or malformed documents out (write-side twin of handleParseAuth's
	// read-side ownership check).
	doc, err := normalizeQoderAuthDoc(raw)
	if err != nil {
		return err
	}
	if raw, err = json.Marshal(doc); err != nil {
		return err
	}
	// v0.8.27: typed buildAuthFileJSON rebuilds (lifecycle notes, adopt,
	// import) construct a fresh document and would silently drop the
	// persisted model_cache snapshot. Re-inject whitelisted plugin-stamped
	// keys the caller didn't set but the physical file carries.
	raw = preservePluginDocKeys(name, raw)
	saveReq := pluginapi.HostAuthSaveRequest{
		Name: name,
		JSON: raw,
	}
	saveBody, _ := json.Marshal(saveReq)
	rawResp, err := hostCall(pluginabi.MethodHostAuthSave, saveBody)
	if err != nil {
		return fmt.Errorf("host.auth.save: %w", err)
	}
	var env envelope
	if err := json.Unmarshal(rawResp, &env); err != nil || !env.OK {
		msg := "host.auth.save failed"
		if env.Error != nil && env.Error.Message != "" {
			msg = truncateRedacted(env.Error.Message, 200)
		}
		return fmt.Errorf("%s", msg)
	}
	return nil
}

// mergeAuthStorageJSON overlays provider-owned auth/account values onto the
// complete credential document while preserving CPA/UI metadata and fields
// unknown to the current plugin version.
func mergeAuthStorageJSON(raw []byte, sa *storedAuth) ([]byte, error) {
	if sa == nil {
		return nil, fmt.Errorf("nil storedAuth")
	}
	doc := map[string]json.RawMessage{}
	if len(strings.TrimSpace(string(raw))) > 0 {
		if err := json.Unmarshal(raw, &doc); err != nil {
			return nil, err
		}
		if doc == nil {
			doc = map[string]json.RawMessage{}
		}
	}
	var source map[string]json.RawMessage
	if len(strings.TrimSpace(string(sa.rawJSON))) > 0 && json.Unmarshal(sa.rawJSON, &source) == nil && source != nil {
		if len(doc) == 0 {
			doc = source
		} else {
			_, currentNested := doc["auth"]
			for key, value := range source {
				if key == "auth" || key == "account" || (currentNested && isFlatAuthField(key)) {
					continue
				}
				if _, exists := doc[key]; !exists {
					doc[key] = value
				}
			}
		}
	}
	if _, currentNested := doc["auth"]; !currentNested {
		if sourceAuth, sourceNested := source["auth"]; sourceNested {
			doc["auth"] = sourceAuth
			if sourceAccount, ok := source["account"]; ok {
				doc["account"] = sourceAccount
			}
			for key := range doc {
				if isFlatAuthField(key) {
					delete(doc, key)
				}
			}
		}
	}
	storage, err := json.Marshal(sa)
	if err != nil {
		return nil, err
	}
	var nested map[string]json.RawMessage
	if err := json.Unmarshal(storage, &nested); err != nil {
		return nil, err
	}
	if _, nestedShape := doc["auth"]; nestedShape {
		if source != nil {
			if sourceAuth, ok := source["auth"]; ok {
				doc["auth"], err = mergeJSONObjects(sourceAuth, doc["auth"])
				if err != nil { return nil, err }
			}
			if sourceAccount, ok := source["account"]; ok {
				doc["account"], err = mergeJSONObjects(sourceAccount, doc["account"])
				if err != nil { return nil, err }
			}
		}
		doc["auth"], err = mergeJSONObjects(doc["auth"], nested["auth"])
		if err != nil { return nil, err }
		doc["account"], err = mergeJSONObjects(doc["account"], nested["account"])
		if err != nil { return nil, err }
	} else {
		set := func(key string, value any) error {
			encoded, err := json.Marshal(value)
			if err != nil { return err }
			doc[key] = encoded
			return nil
		}
		for key, value := range map[string]any{
			"accessToken": sa.Auth.AccessToken, "refreshToken": sa.Auth.RefreshToken,
			"personalToken": sa.Auth.PersonalToken, "expiresAt": sa.Auth.ExpiresAt,
			"domain": sa.Auth.Domain, "region": sa.Auth.Region,
			"uid": sa.Account.UID, "enterpriseId": sa.Account.EnterpriseID,
			"nickname": sa.Account.Nickname,
		} {
			if err := set(key, value); err != nil { return nil, err }
		}
	}
	doc["type"] = json.RawMessage(`"qoder"`)
	doc["provider"] = json.RawMessage(`"qoder"`)
	doc["auth_kind"] = json.RawMessage(`"oauth"`)
	return json.Marshal(doc)
}

func isFlatAuthField(key string) bool {
	switch key {
	case "accessToken", "refreshToken", "personalToken", "expiresAt", "domain", "region", "uid", "enterpriseId", "nickname":
		return true
	default:
		return false
	}
}

func mergeJSONObjects(existing, replacement json.RawMessage) (json.RawMessage, error) {
	var out map[string]json.RawMessage
	if len(existing) > 0 && string(existing) != "null" {
		if err := json.Unmarshal(existing, &out); err != nil { out = nil }
	}
	if out == nil { out = make(map[string]json.RawMessage) }
	var next map[string]json.RawMessage
	if err := json.Unmarshal(replacement, &next); err != nil { return nil, err }
	for key, value := range next { out[key] = value }
	return json.Marshal(out)
}

func storageJSONForAuth(sa *storedAuth) []byte {
	if sa == nil { return nil }
	if len(sa.rawJSON) > 0 {
		if merged, err := mergeAuthStorageJSON(sa.rawJSON, sa); err == nil { return merged }
		return append([]byte(nil), sa.rawJSON...)
	}
	raw, _ := json.Marshal(sa)
	return raw
}

// authMetadataFromJSON extracts host-managed top-level metadata without
// copying provider-owned credential fields into AuthData.Metadata.
func authMetadataFromJSON(raw []byte) map[string]any {
	var doc map[string]any
	if len(strings.TrimSpace(string(raw))) == 0 || json.Unmarshal(raw, &doc) != nil { return nil }
	out := make(map[string]any)
	for key, value := range doc {
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "auth", "account", "accesstoken", "refreshtoken", "personaltoken", "expiresat", "domain", "region", "uid", "enterpriseid", "nickname":
			continue
		default:
			out[key] = value
		}
	}
	if len(out) == 0 { return nil }
	return out
}

func metadataBool(value any) bool {
	switch v := value.(type) {
	case bool: return v
	case string: return strings.EqualFold(strings.TrimSpace(v), "true") || strings.TrimSpace(v) == "1"
	case float64: return v != 0
	default: return false
	}
}

func mergeAuthMetadata(sa *storedAuth, existing map[string]any, disabled bool, prevCredits string) map[string]any {
	defaults := enrichAuthMetadataWithPrev(sa, nil, disabled, prevCredits)
	out := make(map[string]any, len(existing)+len(defaults))
	for key, value := range existing { out[key] = value }
	for key, value := range defaults { if _, ok := out[key]; !ok { out[key] = value } }
	out["type"] = providerName
	out["provider"] = providerName
	out["auth_kind"] = "oauth"
	out["disabled"] = disabled
	return out
}

func authForPhysicalSave(phys *hostAuthPhysical, fallback *storedAuth) *storedAuth {
	if phys != nil && len(phys.JSON) > 0 {
		if current, err := parseStored(phys.JSON); err == nil {
			if fallback != nil && len(fallback.rawJSON) > 0 {
				// Callers may intentionally override identity/routing fields
				// (adoption rewrites region/domain) that the physical file still
				// carries. Copy only those intent fields onto the fresh snapshot
				// so lifecycle writes never resurrect a stale token.
				if r := strings.TrimSpace(fallback.Auth.Region); r != "" {
					current.Auth.Region = r
				}
				if d := strings.TrimSpace(fallback.Auth.Domain); d != "" {
					current.Auth.Domain = d
				}
			}
			return current
		}
	}
	return fallback
}

func buildAuthFileJSONPreserving(phys *hostAuthPhysical, sa *storedAuth, disabled bool, note string, extra map[string]any) ([]byte, error) {
	if phys == nil || len(phys.JSON) == 0 {
		return buildAuthFileJSON(sa, disabled, note, extra)
	}
	sa = authForPhysicalSave(phys, sa)
	if sa == nil {
		return nil, fmt.Errorf("nil storedAuth")
	}
	raw, err := mergeAuthStorageJSON(phys.JSON, sa)
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	doc["type"] = providerName
	doc["provider"] = providerName
	doc["auth_kind"] = "oauth"
	doc["logo"] = pluginLogoURL
	doc["disabled"] = disabled
	doc["note"] = note
	for key, value := range extra { doc[key] = value }
	return json.Marshal(doc)
}

// lifecycleStateUnchanged avoids redundant saves when note/disabled unchanged.

func buildAuthFileJSON(sa *storedAuth, disabled bool, note string, extra map[string]any) ([]byte, error) {
	if sa == nil {
		return nil, fmt.Errorf("nil storedAuth")
	}
	var out map[string]any
	if len(sa.rawJSON) > 0 {
		raw, err := mergeAuthStorageJSON(sa.rawJSON, sa)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, &out); err != nil {
			return nil, err
		}
	} else {
		storage, err := json.Marshal(sa)
		if err != nil { return nil, err }
		var nested map[string]any
		if err := json.Unmarshal(storage, &nested); err != nil { return nil, err }
		out = map[string]any{"auth": nested["auth"], "account": nested["account"]}
	}
	out["type"] = providerName
	out["provider"] = providerName
	out["auth_kind"] = "oauth"
	out["logo"] = pluginLogoURL
	out["disabled"] = disabled
	out["note"] = note
	for k, v := range extra {
		out[k] = v
	}
	// extra must not be able to strip the classification.
	out["auth_kind"] = "oauth"
	return json.Marshal(out)
}

// parseDisabledFromAuthJSON reads top-level disabled from physical auth JSON.

func parseDisabledFromAuthJSON(raw []byte) bool {
	var m struct {
		Disabled bool `json:"disabled"`
	}
	_ = json.Unmarshal(raw, &m)
	return m.Disabled
}

// isSafeAuthPath rejects non-qoderwork filenames, empty paths, and
// traversal attempts. It validates both the basename pattern AND that the path
// does not escape via ".." segments. Callers that need to confine deletes to
// a specific directory should additionally check isPathUnder(path, dir).

func isSafeAuthPath(path string) bool {
	path = strings.TrimSpace(path)
	if path == "" {
		return false
	}
	// Reject any path containing ".." — prevents traversal regardless of basename.
	if strings.Contains(filepath.ToSlash(path), "../") || strings.Contains(filepath.ToSlash(path), "/..") {
		return false
	}
	base := filepath.Base(path)
	lower := strings.ToLower(base)
	if !strings.HasPrefix(lower, providerName+"-") && lower != "qoderwork.json" {
		return false
	}
	if !strings.HasSuffix(lower, ".json") {
		return false
	}
	// Path traversal / absolute weirdness: base must equal cleaned base.
	if base != filepath.Base(filepath.Clean(path)) {
		return false
	}
	return true
}

// isPathUnder reports whether path is inside dir (after cleaning both).
// Empty dir means "no constraint" (returns true for any safe path).

func isPathUnder(path, dir string) bool {
	path = strings.TrimSpace(path)
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return true
	}
	cleanPath := filepath.Clean(path)
	cleanDir := filepath.Clean(dir)
	if cleanPath == cleanDir {
		return false // path is the dir itself, not under it
	}
	rel, err := filepath.Rel(cleanDir, cleanPath)
	if err != nil {
		return false
	}
	return rel != "." && !strings.HasPrefix(rel, "..") && !strings.Contains(rel, string(filepath.Separator)+"..")
}

// deleteAuthFileInDir is like deleteAuthFileAt but additionally requires the
// path to be under dir. Use for lifecycle deletes where the auth directory is
// known — prevents a malicious/buggy host path from deleting arbitrary files.
// The path MUST be absolute (defense against relative-path CWD deletion).

func deleteAuthFileInDir(path, dir string) error {
	if !isSafeAuthPath(path) {
		return fmt.Errorf("refusing to delete unsafe path: %s", path)
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("refusing to delete relative path: %s", path)
	}
	if dir != "" && !isPathUnder(path, dir) {
		return fmt.Errorf("refusing to delete path outside auth dir: %s (dir=%s)", path, dir)
	}
	err := os.Remove(path)
	if err != nil && os.IsNotExist(err) {
		return nil
	}
	return err
}
