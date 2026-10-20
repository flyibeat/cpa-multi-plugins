// adopt.go migrates legacy qoder-cn / qoder-intl auth files to the merged
// qoder provider (v0.10.0).
//
// History: qoder-cn (openapi.qoder.com.cn) and qoder-intl (openapi.qoder.sh)
// were separate plugins against DIFFERENT backends, so unlike the workbuddy
// merge (same backend → dedupe by UID) there is NO dedupe here. Filenames
// are KEPT — qoder-cn-<uid>.json / qoder-intl-<uid>.json already carry the
// canonical "qoder-" prefix — and only the JSON is rewritten in place:
//
//	type/provider: qoder-cn | qoder-intl → qoder
//	auth.region:   cn | intl (explicit; region derived from the filename)
//	auth.domain:   qoder.com.cn | qoder.com (the intl plugin hardcoded the CN domain)
//
// The host routes auth files to plugins by the file's type field, so without
// this rewrite legacy files would be orphaned. Idempotent (files already
// carrying type "qoder" + an explicit region are skipped), guarded by a min
// re-run interval, and never blocks plugin registration (background).
package main

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

var (
	adoptMu      sync.Mutex
	lastAdoptRun time.Time
)

// startAdoption kicks the background migration. Safe to call on every
// register/reconfigure — the guard collapses repeated calls.
//
// v0.8.29 (issue #22): during plugin registration the host auth manager may
// not be wired yet — host.auth.list falls back to the auth directory and
// returns entries whose auth_index host.auth.get cannot resolve ("bad
// envelope"), and adoption silently never ran. Retry until the manager-backed
// view is available; the direct-by-path fallback inside adoptForeignAuths
// makes each attempt independent of manager readiness.
func startAdoption() {
	go func() {
		adoptMu.Lock()
		if !lastAdoptRun.IsZero() && time.Since(lastAdoptRun) < time.Minute {
			adoptMu.Unlock()
			return
		}
		lastAdoptRun = time.Now()
		adoptMu.Unlock()
		for attempt := 0; attempt < 10; attempt++ {
			if attempt > 0 {
				time.Sleep(2 * time.Second)
			}
			if adoptForeignAuths() {
				return
			}
		}
		log.Printf("adopt: host auth manager did not become ready; will retry on next reload")
	}()
}

// legacyQoderRegion maps a legacy auth file name to its region ("" = not legacy).
func legacyQoderRegion(name string) string {
	lower := strings.ToLower(strings.TrimSpace(name))
	switch {
	case strings.HasPrefix(lower, "qoder-intl-"), lower == "qoder-intl.json":
		return regionIntl
	case strings.HasPrefix(lower, "qoder-cn-"), lower == "qoder-cn.json":
		return regionCN
	}
	return ""
}

// adoptForeignAuths rewrites every legacy qoder-cn/qoder-intl auth file in
// place (same filename, updated JSON). Returns true when every legacy
// candidate was resolvable (or none exist), false when the host still needs
// time to publish auth indexes (caller retries).
func adoptForeignAuths() bool {
	files, err := hostAuthListFn()
	if err != nil {
		log.Printf("adopt: host auth list failed: %v", err)
		return false
	}
	adopted := 0
	waitingForHost := false
	for _, f := range files {
		region := legacyQoderRegion(f.Name)
		if region == "" {
			continue
		}
		phys, err := hostAuthGetPhysical(f.AuthIndex)
		if err != nil || phys == nil {
			// Manager not ready (bad envelope / empty index): the list entry
			// carries the backing path — read the physical file directly
			// (issue #22; verified independently by the reporter).
			phys = readPhysicalFromListEntry(f)
			if phys == nil {
				waitingForHost = true
				log.Printf("adopt %s: get failed: %v", f.Name, err)
				continue
			}
		}
		var probe struct {
			Type string `json:"type"`
		}
		_ = json.Unmarshal(phys.JSON, &probe)
		if strings.EqualFold(strings.TrimSpace(probe.Type), providerName) {
			continue // already canonical (this run or a previous one)
		}
		sa, err := parseStored(phys.JSON)
		if err != nil || sa == nil {
			log.Printf("adopt %s: unparsable — left in place (re-import manually)", f.Name)
			continue
		}
		sa.Auth.Region = region
		sa.Auth.Domain = domainForRegion(region)
		disabled := parseDisabledFromAuthJSON(phys.JSON)
		note := "migrated from " + map[string]string{regionCN: "qoder-cn", regionIntl: "qoder-intl"}[region]
		if raw, err := buildAuthFileJSONPreserving(phys, sa, disabled, note, nil); err == nil {
			if err := hostAuthSaveJSONFn(f.Name, raw); err != nil {
				log.Printf("adopt %s: save failed: %v", f.Name, err)
				continue
			}
			log.Printf("adopt %s: type→%s, region=%s", f.Name, providerName, region)
			adopted++
		} else {
			log.Printf("adopt %s: encode failed: %v", f.Name, err)
		}
	}
	if adopted > 0 {
		log.Printf("adopt: done — migrated %d legacy qoder auth file(s)", adopted)
	}
	return !waitingForHost
}

// readPhysicalFromListEntry builds the physical view straight from the
// host.auth.list entry's backing path. Best-effort: empty path or unreadable
// file returns nil so the caller's retry ladder takes over.
func readPhysicalFromListEntry(f pluginapi.HostAuthFileEntry) *hostAuthPhysical {
	path := strings.TrimSpace(f.Path)
	if path == "" {
		return nil
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil
	}
	raw, err := os.ReadFile(abs)
	if err != nil || len(raw) == 0 {
		return nil
	}
	return &hostAuthPhysical{
		AuthIndex: f.AuthIndex,
		Name:      f.Name,
		Path:      abs,
		JSON:      raw,
		Disabled:  parseDisabledFromAuthJSON(raw),
	}
}
