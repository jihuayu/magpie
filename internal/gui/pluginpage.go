package gui

import (
	"cmp"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yetone/magpie/internal/plugin"
	"github.com/yetone/magpie/internal/provider"
	"github.com/yetone/magpie/internal/usage"
)

// A community plugin's own page in magpie's window (P4 of
// docs/subsystems/plugin-runtime.md): package.json's magpie.page, shown in
// a sandboxed frame (pluginpages.js), and its panels in magpie's own pages
// (magpie.panels, P5), each in a frame of its own shut in the same way.
// Their files are served under
// pluginPagePrefix and a token only this run of magpie hands out, with a
// policy that lets the page load nothing but its own files and reach
// nothing over the network; it has no way to magpie's /api (apiFramed),
// and what it may read of magpie's it asks the window for, which asks
// /api/plugin-pages/read for the reads its package declared.

// pluginPagePrefix is where a plugin's page's files are served:
// pluginPagePrefix + token + "/" + the file's path in the page's folder.
const pluginPagePrefix = "/_magpie/plugin/"

// pluginBridgePath is the window's side of the page's messages, served
// beside every page's files: a page loads it as
// <script src="_magpie/bridge.js">.
const pluginBridgePath = "_magpie/bridge.js"

//go:embed pagebridge.js
var pageBridgeJS []byte

// pageSecret keys this run's tokens: a token from an earlier run, or one
// made up, serves nothing.
var pageSecret = func() []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}()

func pageToken(spec string) string {
	m := hmac.New(sha256.New, pageSecret)
	m.Write([]byte(spec))
	return hex.EncodeToString(m.Sum(nil)[:16])
}

// pluginPage is a plugin's page, of a plugin that is on.
type pluginPage struct {
	Spec  string `json:"spec"`
	Name  string `json:"name"`  // its package's
	Key   string `json:"key"`   // the window's page key
	Title string `json:"title"` // the page's, or the package's magpie.name or short name
	// Titles are its title by the window's language (plugin.PageSpec)
	Titles map[string]string `json:"titles,omitempty"`
	URL    string            `json:"url"` // the page, under pluginPagePrefix
	Icon   string            `json:"icon,omitempty"`
	// Replaces is the built-in page whose place it takes: the first
	// plugin's in plugins.json's order to ask for it
	Replaces string   `json:"replaces,omitempty"`
	Reads    []string `json:"reads"` // what it may read, of plugin.PageReads
	// Methods are the methods the page may call of its plugin
	// (magpie.page.actions): only these reach /api/plugin-pages/invoke
	Methods []string `json:"methods,omitempty"`
	// Confirm are the methods the window asks the reader about first
	// (magpie.page.confirm); the window takes a one-time confirmId
	Confirm []string `json:"confirm,omitempty"`
	// Actions are its items in magpie's menus (plugin.ActionSpec); each
	// opens this page
	Actions []pluginAction `json:"actions,omitempty"`
	// Service is where a browser reaches the page's local service
	// (plugin.ServiceSpec) through this server, relative to the page's own
	// address: only on a page served to a browser (servePageService)
	Service string `json:"service,omitempty"`
	// KeepAlive keeps its frame while the reader is on another page
	// (plugin.PageSpec); else the window lets it go after a while hidden
	KeepAlive bool `json:"keepAlive,omitempty"`
	token     string
	dir       string
	file      string // its HTML, relative to dir, with forward slashes
	hosted    bool   // its plugin has a part for the host too (pageHost)
	service   *plugin.ServiceSpec
	options   map[string]any // its plugin's, as plugins.json keeps them
}

// pluginAction is an item a plugin's page adds to one of magpie's menus.
type pluginAction struct {
	ID     string            `json:"id"`
	Menu   string            `json:"menu"`  // of plugin.ActionMenus
	Title  string            `json:"title"` // its own, or its page's
	Titles map[string]string `json:"titles,omitempty"`
}

// pluginPanel is a panel a plugin that is on adds to one of magpie's own
// pages (plugin.PanelSlots).
type pluginPanel struct {
	Spec   string            `json:"spec"`
	Name   string            `json:"name"`  // its package's
	Key    string            `json:"key"`   // the panel's, among every plugin's
	Slot   string            `json:"slot"`  // the page it is in
	Title  string            `json:"title"` // the panel's, or the package's magpie.name or short name
	Titles map[string]string `json:"titles,omitempty"`
	URL    string            `json:"url"`   // the panel, under pluginPagePrefix
	Reads  []string          `json:"reads"` // what it may read, of plugin.PageReads
	token  string
	dir    string
	file   string
	hosted bool
}

// pageKeyChars are what a window page's key can't have
var pageKeyChars = strings.NewReplacer("@", "", "/", "-", ".", "-", "_", "-", " ", "-")

// windowParts are the pages and the panels of the plugins that are on, in
// plugins.json's order. A plugin switched off has none: its files aren't
// served.
func windowParts() (pages []pluginPage, panels []pluginPanel) {
	seen := map[string]bool{}
	replaced := map[string]bool{}
	for _, e := range plugin.Load().Plugins {
		if e.Off {
			continue
		}
		w, only := plugin.Window(plugin.Target(e.Spec))
		if w == nil {
			continue
		}
		name := plugin.PackageName(e.Spec)
		key := "plugin-" + strings.Trim(pageKeyChars.Replace(strings.ToLower(plugin.ShortName(name))), "-")
		key = strings.Map(func(r rune) rune {
			if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' {
				return r
			}
			return -1
		}, key)
		for k, n := key, 2; seen[key]; n++ {
			key = fmt.Sprintf("%s-%d", k, n)
		}
		seen[key] = true
		reads := w.Reads
		if reads == nil {
			reads = []string{}
		}
		if spec := w.Page; spec != nil {
			tok := pageToken(e.Spec)
			rel, _ := filepath.Rel(spec.Dir, spec.File)
			p := pluginPage{Spec: e.Spec, Name: name, Key: key, Title: spec.Title, Titles: spec.Titles, Reads: reads, Methods: spec.Actions, Confirm: spec.Confirm, token: tok, dir: spec.Dir,
				URL: pluginPagePrefix + tok + "/" + filepath.ToSlash(rel), file: filepath.ToSlash(rel), hosted: !only, options: e.Options, KeepAlive: spec.KeepAlive}
			if !only {
				p.service = spec.Service
			}
			if p.Title == "" {
				p.Title = cmp.Or(plugin.InstalledName(e.Spec), plugin.ShortName(name))
			}
			if spec.Icon != "" {
				p.Icon = pluginPagePrefix + tok + "/" + spec.Icon
			}
			if r := spec.Replaces; r != "" && !replaced[r] {
				replaced[r] = true
				p.Replaces = r
			}
			for _, a := range w.Actions {
				act := pluginAction{ID: a.ID, Menu: a.Menu, Title: a.Title, Titles: a.Titles}
				// one that names no title is the page's own, in each language
				if act.Title == "" {
					act.Title, act.Titles = p.Title, p.Titles
				}
				p.Actions = append(p.Actions, act)
			}
			pages = append(pages, p)
		}
		for i, spec := range w.Panels {
			tok := pageToken(e.Spec + "\x00panel\x00" + strconv.Itoa(i))
			rel, _ := filepath.Rel(spec.Dir, spec.File)
			p := pluginPanel{Spec: e.Spec, Name: name, Key: fmt.Sprintf("%s-%d", key, i), Slot: spec.Slot, Title: spec.Title, Titles: spec.Titles, Reads: reads,
				token: tok, dir: spec.Dir, URL: pluginPagePrefix + tok + "/" + filepath.ToSlash(rel), file: filepath.ToSlash(rel), hosted: !only}
			if p.Title == "" {
				p.Title = cmp.Or(plugin.InstalledName(e.Spec), plugin.ShortName(name))
			}
			panels = append(panels, p)
		}
	}
	return pages, panels
}

// pluginPages are the pages of the plugins that are on.
func pluginPages() []pluginPage {
	pages, _ := windowParts()
	return pages
}

// windowOf is a plugin that is on and adds a page or a panel to the
// window: its package's name and the reads it declared.
func windowOf(spec string) (name string, reads []string, ok bool) {
	pages, panels := windowParts()
	for _, p := range pages {
		if p.Spec == spec {
			return p.Name, p.Reads, true
		}
	}
	for _, p := range panels {
		if p.Spec == spec {
			return p.Name, p.Reads, true
		}
	}
	return "", nil, false
}

// pagePolicy is what a plugin's page may load and reach: its own files,
// inline styles, data: pictures, and nothing over the network. sandbox
// keeps a page opened by itself (not in the window's frame) as shut in as
// the frame keeps it.
func pagePolicy(r *http.Request, tok string) string {
	own := "'self'"
	if r.Host != "" {
		// the page's own folder: not the window's files, nor /api
		own = strings.Join(ownSources(r, pluginPagePrefix+tok+"/"), " ")
	}
	return strings.Join([]string{
		"sandbox allow-scripts",
		"default-src 'none'",
		"script-src " + own,
		"style-src " + own + " 'unsafe-inline'",
		"img-src " + own + " data:",
		"font-src " + own,
		"media-src " + own,
		"connect-src 'none'",
		"frame-src 'none'",
		"worker-src 'none'",
		"object-src 'none'",
		"form-action 'none'",
		"base-uri 'none'",
		"frame-ancestors 'self'",
	}, "; ")
}

// ownSources are the sources, with their scheme, that name path on the
// address r came to. A sandboxed frame's origin is opaque, and a source
// with no scheme takes its scheme from that origin: iOS Safari (iOS 18.7)
// matched the scheme-less host/path to nothing and never asked for a
// page's scripts, so the page was broken at 10s (#4198, orinsid and
// YangHonghang). Chromium, and the newer WebKit Playwright runs, take
// the scheme from the URL loaded, which is why only the iPhone failed.
//
// The desktop window names its own transport (ownWindow): wails://, or
// http:// on Windows (#2501). A browser's page (magpie web) can come over
// http or https, directly or through a proxy that ends TLS before magpie
// (nginx, Cloudflare), and nothing magpie trusts says which, so both are
// named: the same host, port and folder either way, and an https page
// can't load http:// files anyway (mixed content).
func ownSources(r *http.Request, path string) []string {
	if scheme, _ := r.Context().Value(windowSchemeKey{}).(string); scheme != "" {
		return []string{scheme + "://" + r.Host + path}
	}
	return []string{"https://" + r.Host + path, "http://" + r.Host + path}
}

// pageHostWait is how long a page's HTML waits for its plugin's host,
// short of the window's 10 seconds for the page to say hello
// (pluginpages.js's HELLO_MS).
var pageHostWait = 7 * time.Second

// warmHost starts the plugin host if it isn't up; tests replace it.
var warmHost = plugin.Warm

// pageHost has the plugin host up for a page whose plugin has a part for
// it too, waiting pageHostWait at most. Such a page can be the way into
// a service that part runs: Magiczerowxy/magpie-chat's page sends its
// frame to the chat server its host part starts. The host starts only on
// a call, and every Restart (a plugin installed, updated or set, a Bun
// update) stops it until the next one, so with no other plugin asking,
// the page went to a server that wasn't there: Chromium shows its
// connection error, and WebKit (the Mac's and Linux's window) leaves the
// frame on the page's own "connecting…" for good. The host starts in the
// background under its own two minutes, as every caller's does, so a
// slow one isn't cut off when the page stops waiting.
func pageHost(ctx context.Context) {
	done := make(chan struct{})
	warm := warmHost // read here: the start can outlive the page's wait
	go func() {
		defer close(done)
		c, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if err := warm(c); err != nil {
			log.Printf("plugin page: starting the plugin host: %v", err)
		}
	}()
	t := time.NewTimer(pageHostWait)
	defer t.Stop()
	select {
	case <-done:
	case <-t.C:
	case <-ctx.Done():
	}
}

// servePluginPage serves a file of a plugin's page, by its token, and on
// a page served to a browser (web) the page's local service too.
func servePluginPage(rw http.ResponseWriter, r *http.Request, web bool) {
	rest := strings.TrimPrefix(r.URL.Path, pluginPagePrefix)
	tok, rel, ok := strings.Cut(rest, "/")
	if !ok || len(tok) != 32 {
		http.NotFound(rw, r)
		return
	}
	// the page's or the panel's folder, by its token
	dir, entry, hosted := "", "", false
	var page *pluginPage
	pages, panels := windowParts()
	for i, p := range pages {
		if hmac.Equal([]byte(p.token), []byte(tok)) {
			dir, entry, hosted = p.dir, p.file, p.hosted
			page = &pages[i]
		}
	}
	// the service's paths are never a file of the page's
	if strings.HasPrefix(rel, pageServicePath) {
		if !web || page == nil || page.servicePort() == 0 {
			http.NotFound(rw, r)
			return
		}
		servePageService(rw, r, page, tok)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	for _, p := range panels {
		if hmac.Equal([]byte(p.token), []byte(tok)) {
			dir, entry, hosted = p.dir, p.file, p.hosted
		}
	}
	if dir == "" {
		http.NotFound(rw, r)
		return
	}
	// the page itself, of a plugin with a part for the host: that part is
	// up before the page is (pageHost)
	if hosted && rel == entry {
		pageHost(r.Context())
	}
	h := rw.Header()
	h.Set("Content-Security-Policy", pagePolicy(r, tok))
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	// no Cross-Origin-Resource-Policy: to the page's sandboxed frame, an
	// origin of its own, its own files are another origin's, and
	// same-origin (or same-site) would block every one of them
	h.Set("Cache-Control", "no-cache")
	if rel == pluginBridgePath {
		h.Set("Content-Type", "text/javascript; charset=utf-8")
		http.ServeContent(rw, r, "bridge.js", time.Time{}, strings.NewReader(string(pageBridgeJS)))
		return
	}
	file, ok := plugin.FileIn(dir, rel)
	if !ok {
		http.NotFound(rw, r)
		return
	}
	// ServeContent, not ServeFile: ServeFile sends .../index.html to ./,
	// which a page's own links needn't follow.
	f, err := os.Open(file)
	if err != nil {
		http.NotFound(rw, r)
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.IsDir() {
		http.NotFound(rw, r)
		return
	}
	http.ServeContent(rw, r, filepath.Base(file), st.ModTime(), f)
}

// apiFramed is whether r is a request for /api that no page of the window's
// own makes: one from a sandboxed frame (Origin: null, which a plugin's
// page's fetch would send were its policy not to stop it), one that loads
// /api into a frame, or one another site's page sends. The desktop
// window's /api has no key, so this is what keeps a plugin's page out.
func apiFramed(r *http.Request) bool {
	if !strings.HasPrefix(r.URL.Path, "/api/") {
		return false
	}
	if r.Header.Get("Origin") == "null" {
		return true
	}
	switch r.Header.Get("Sec-Fetch-Dest") {
	case "iframe", "frame", "embed", "object":
		return true
	}
	return r.Header.Get("Sec-Fetch-Site") == "cross-site" && r.Header.Get("Sec-Fetch-Dest") != "document"
}

// callPageInvoke runs one of a page's methods in its plugin. It is
// plugin.Call, replaced in tests that run no host.
var callPageInvoke = plugin.Call

// pageConfirmation is a one-time grant the window got after asking the
// reader about a method in magpie.page.confirm. It names the page, the
// method and the arguments it was granted for, and expires.
type pageConfirmation struct {
	spec, method, hash string
	expires            time.Time
}

var pageConfirmations = struct {
	sync.Mutex
	m map[string]pageConfirmation
}{m: map[string]pageConfirmation{}}

// confirmHash is what a confirmation is bound to: the page, the method and
// the arguments exactly as the window sent them.
func confirmHash(spec, method string, args []byte) string {
	h := sha256.New()
	h.Write([]byte(spec))
	h.Write([]byte{0})
	h.Write([]byte(method))
	h.Write([]byte{0})
	h.Write(args)
	return hex.EncodeToString(h.Sum(nil))
}

// issuePageConfirm grants one call of spec's method with args: a random
// id, good for a minute and once.
func issuePageConfirm(spec, method string, args []byte) (string, bool) {
	now := time.Now()
	pageConfirmations.Lock()
	defer pageConfirmations.Unlock()
	for id, c := range pageConfirmations.m {
		if now.After(c.expires) {
			delete(pageConfirmations.m, id)
		}
	}
	if len(pageConfirmations.m) >= 512 {
		return "", false
	}
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", false
	}
	id := hex.EncodeToString(b)
	pageConfirmations.m[id] = pageConfirmation{spec: spec, method: method, hash: confirmHash(spec, method, args), expires: now.Add(time.Minute)}
	return id, true
}

// takePageConfirm uses up the grant id for spec's method with args, if it
// is that one and not expired.
func takePageConfirm(id, spec, method string, args []byte) bool {
	pageConfirmations.Lock()
	defer pageConfirmations.Unlock()
	c, ok := pageConfirmations.m[id]
	if !ok {
		return false
	}
	delete(pageConfirmations.m, id)
	return !time.Now().After(c.expires) && c.spec == spec && c.method == method && c.hash == confirmHash(spec, method, args)
}

// A page method may run on past its request: the window asks for a job,
// gets an id and asks for its state, and may cancel it. The job lives in
// this process only; magpie restarted loses the list, not the plugin's
// own state.
type pageJob struct {
	id, spec, method string
	state            string
	result           json.RawMessage
	err              string
	started, ended   time.Time
	cancel           context.CancelFunc
}

var pageJobs = struct {
	sync.Mutex
	m map[string]*pageJob
}{m: map[string]*pageJob{}}

// startPageJob runs one of a page's methods in the background, within
// half an hour, and answers its id.
func startPageJob(spec, method string, args json.RawMessage) (string, bool) {
	now := time.Now()
	pageJobs.Lock()
	for id, j := range pageJobs.m {
		if !j.ended.IsZero() && now.Sub(j.ended) > time.Hour {
			delete(pageJobs.m, id)
		}
	}
	if len(pageJobs.m) >= 100 {
		pageJobs.Unlock()
		return "", false
	}
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		pageJobs.Unlock()
		return "", false
	}
	id := "job-" + hex.EncodeToString(b)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	j := &pageJob{id: id, spec: spec, method: method, state: "running", started: now, cancel: cancel}
	pageJobs.m[id] = j
	pageJobs.Unlock()
	go func() {
		var out json.RawMessage
		err := callPageInvoke(ctx, "pageInvoke", map[string]any{"spec": spec, "method": method, "args": args, "ms": 30 * 60 * 1000}, &out)
		pageJobs.Lock()
		defer pageJobs.Unlock()
		j.ended = time.Now()
		j.cancel = nil
		if ctx.Err() == context.Canceled {
			j.state = "canceled"
			return
		}
		if err != nil {
			j.state = "failed"
			j.err = err.Error()
			return
		}
		j.state = "done"
		if len(out) == 0 {
			out = json.RawMessage("null")
		}
		j.result = out
	}()
	return id, true
}

// pageJobState is one job as the window sees it.
func pageJobState(id string) (map[string]any, bool) {
	pageJobs.Lock()
	defer pageJobs.Unlock()
	j, ok := pageJobs.m[id]
	if !ok {
		return nil, false
	}
	out := map[string]any{"id": j.id, "spec": j.spec, "method": j.method, "state": j.state,
		"started": j.started, "result": j.result, "error": j.err}
	if !j.ended.IsZero() {
		out["ended"] = j.ended
	}
	return out, true
}

func cancelPageJob(id string) bool {
	pageJobs.Lock()
	defer pageJobs.Unlock()
	j, ok := pageJobs.m[id]
	if !ok || j.cancel == nil {
		return false
	}
	j.cancel()
	j.cancel = nil
	return true
}

// pageEventJSON is one event of a page's stream, as the window's
// EventSource gets it.
type pageEventJSON struct {
	Kind   string          `json:"kind"`
	Name   string          `json:"name,omitempty"`
	CallID string          `json:"callId,omitempty"`
	Method string          `json:"method,omitempty"`
	Args   json.RawMessage `json:"args,omitempty"`
	Data   json.RawMessage `json:"data,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
	OK     bool            `json:"ok,omitempty"`
	Error  string          `json:"error,omitempty"`
}

// pageEventHub fans a plugin's page stream out to the window looking at
// that page. A stream nobody reads drops its events; the page's frame
// gets them one at a time through a MessagePort.
type pageEventHub struct {
	mu   sync.Mutex
	subs map[string]map[chan []byte]struct{}
}

var pageEvents = pageEventHub{subs: map[string]map[chan []byte]struct{}{}}

func (h *pageEventHub) subscribe(spec string) (<-chan []byte, func()) {
	ch := make(chan []byte, 64)
	h.mu.Lock()
	if h.subs[spec] == nil {
		h.subs[spec] = map[chan []byte]struct{}{}
	}
	h.subs[spec][ch] = struct{}{}
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		if _, ok := h.subs[spec][ch]; ok {
			delete(h.subs[spec], ch)
			close(ch)
			if len(h.subs[spec]) == 0 {
				delete(h.subs, spec)
			}
		}
		h.mu.Unlock()
	}
}

func (h *pageEventHub) publish(spec string, b []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs[spec] {
		select {
		case ch <- b:
		default: // the window is behind; its page misses this one
		}
	}
}

var pageEventsOnce sync.Once

// startPageEvents has the host's page events reach the window. Once, since
// a process has one hub.
func startPageEvents() {
	pageEventsOnce.Do(func() {
		plugin.OnPageEvent(func(e plugin.PageEvent) {
			b, err := json.Marshal(pageEventJSON{Kind: e.Kind, Name: e.Name, CallID: e.CallID, Method: e.Method,
				Args: e.Args, Data: e.Data, Result: e.Result, OK: e.OK, Error: e.Error})
			if err != nil {
				return
			}
			pageEvents.publish(e.Spec, b)
		})
	})
}

// pluginPageRoutes are the routes of the plugins' pages and panels. web is
// whether the window is a browser's (isWeb): only there is a page's local
// service served through this server (servePageService), since only there
// can 127.0.0.1 be another computer than this one.
func pluginPageRoutes(mux *http.ServeMux, web bool) {
	startPageEvents()
	mux.HandleFunc(pluginPagePrefix, func(rw http.ResponseWriter, r *http.Request) { servePluginPage(rw, r, web) })
	mux.HandleFunc("GET /api/plugin-pages", func(rw http.ResponseWriter, r *http.Request) {
		out := pluginPages()
		if out == nil {
			out = []pluginPage{}
		}
		for i := range out {
			if web && out[i].servicePort() > 0 {
				out[i].Service = strings.Repeat("../", strings.Count(out[i].file, "/")) + pageServicePath
			}
		}
		writeJSON(rw, out)
	})
	mux.HandleFunc("GET /api/plugin-panels", func(rw http.ResponseWriter, r *http.Request) {
		_, out := windowParts()
		if out == nil {
			out = []pluginPanel{}
		}
		writeJSON(rw, out)
	})
	// what a page or a panel asked the window to read: only what its
	// package declared, and never a secret
	mux.HandleFunc("POST /api/plugin-pages/read", func(rw http.ResponseWriter, r *http.Request) {
		var in struct {
			Spec   string         `json:"spec"`
			Read   string         `json:"read"`
			Params map[string]any `json:"params"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(rw, r.Body, 64<<10)).Decode(&in); err != nil {
			fail(rw, err)
			return
		}
		name, reads, ok := windowOf(in.Spec)
		if !ok {
			fail(rw, errors.New("no plugin page "+in.Spec))
			return
		}
		if !slices.Contains(reads, in.Read) {
			rw.Header().Set("Content-Type", "application/json")
			rw.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(rw).Encode(map[string]string{"error": fmt.Sprintf("%s's package doesn't ask to read %q", name, in.Read)})
			return
		}
		v, err := pageRead(in.Read, in.Params)
		if err != nil {
			fail(rw, err)
			return
		}
		writeJSON(rw, v)
	})
	// the page's stream: events its plugin emits, and calls the plugin
	// makes into the page. Only the window's own EventSource gets it; the
	// page's frame has no way to /api at all.
	mux.HandleFunc("GET /api/plugin-pages/events", func(rw http.ResponseWriter, r *http.Request) {
		spec := r.URL.Query().Get("spec")
		pages, _ := windowParts()
		found := false
		for i := range pages {
			if pages[i].Spec == spec {
				found = true
				break
			}
		}
		if !found {
			http.NotFound(rw, r)
			return
		}
		flusher, ok := rw.(http.Flusher)
		if !ok {
			fail(rw, errors.New("the server can't stream"))
			return
		}
		ch, cancel := pageEvents.subscribe(spec)
		defer cancel()
		rw.Header().Set("Content-Type", "text/event-stream")
		rw.Header().Set("Cache-Control", "no-store")
		rw.Header().Set("X-Accel-Buffering", "no")
		rw.WriteHeader(http.StatusOK)
		flusher.Flush()
		ping := time.NewTicker(15 * time.Second)
		defer ping.Stop()
		for {
			select {
			case <-r.Context().Done():
				return
			case b, ok := <-ch:
				if !ok {
					return
				}
				if _, err := fmt.Fprintf(rw, "data: %s\n\n", b); err != nil {
					return
				}
				flusher.Flush()
			case <-ping.C:
				if _, err := fmt.Fprint(rw, ": keepalive\n\n"); err != nil {
					return
				}
				flusher.Flush()
			}
		}
	})
	// the window asks for a one-time grant before a method its page's
	// package put in magpie.page.confirm: the page can't ask for one, and
	// the grant is bound to the page, the method and these arguments
	mux.HandleFunc("POST /api/plugin-pages/confirm", func(rw http.ResponseWriter, r *http.Request) {
		var in struct {
			Spec   string          `json:"spec"`
			Method string          `json:"method"`
			Args   json.RawMessage `json:"args"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(rw, r.Body, 64<<10)).Decode(&in); err != nil {
			fail(rw, err)
			return
		}
		method := strings.TrimSpace(in.Method)
		pages, _ := windowParts()
		var page *pluginPage
		for i := range pages {
			if pages[i].Spec == in.Spec {
				page = &pages[i]
				break
			}
		}
		if page == nil {
			http.NotFound(rw, r)
			return
		}
		if method == "" || !slices.Contains(page.Confirm, method) {
			rw.Header().Set("Content-Type", "application/json")
			rw.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(rw).Encode(map[string]string{"error": fmt.Sprintf("%s's page doesn't ask before %q", page.Name, method)})
			return
		}
		id, ok := issuePageConfirm(in.Spec, method, in.Args)
		if !ok {
			fail(rw, errors.New("too many confirmations are waiting"))
			return
		}
		writeJSON(rw, map[string]string{"confirmId": id})
	})
	// a page's own methods (magpie.page.actions): only the page's methods
	// reach its plugin, and the plugin's hooks declare what each one does.
	// The window has bound the request to the frame's spec before this, and
	// the host binds it again to the same plugin's hooks.
	mux.HandleFunc("POST /api/plugin-pages/invoke", func(rw http.ResponseWriter, r *http.Request) {
		var in struct {
			Spec       string          `json:"spec"`
			Method     string          `json:"method"`
			Args       json.RawMessage `json:"args"`
			ConfirmID  string          `json:"confirmId"`
			Background bool            `json:"background"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(rw, r.Body, 64<<10)).Decode(&in); err != nil {
			fail(rw, err)
			return
		}
		method := strings.TrimSpace(in.Method)
		if in.Spec == "" || method == "" {
			fail(rw, errors.New("a page and a method are needed"))
			return
		}
		pages, _ := windowParts()
		var page *pluginPage
		for i := range pages {
			if pages[i].Spec == in.Spec {
				page = &pages[i]
				break
			}
		}
		if page == nil {
			http.NotFound(rw, r)
			return
		}
		if !slices.Contains(page.Methods, method) {
			rw.Header().Set("Content-Type", "application/json")
			rw.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(rw).Encode(map[string]string{"error": fmt.Sprintf("%s's page doesn't declare %q", page.Name, method)})
			return
		}
		if slices.Contains(page.Confirm, method) && !takePageConfirm(in.ConfirmID, in.Spec, method, in.Args) {
			rw.Header().Set("Content-Type", "application/json")
			rw.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(rw).Encode(map[string]string{"error": fmt.Sprintf("%s needs a one-time confirmation for %q", page.Name, method)})
			return
		}
		if in.Background {
			id, ok := startPageJob(in.Spec, method, in.Args)
			if !ok {
				fail(rw, errors.New("too many jobs are waiting"))
				return
			}
			writeJSON(rw, map[string]string{"jobId": id})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		var out json.RawMessage
		if err := callPageInvoke(ctx, "pageInvoke", map[string]any{"spec": in.Spec, "method": method, "args": in.Args}, &out); err != nil {
			fail(rw, err)
			return
		}
		if len(out) == 0 {
			out = json.RawMessage("null")
		}
		rw.Header().Set("Content-Type", "application/json")
		_, _ = rw.Write(out)
	})
	// the page's answer to one of its plugin's calls: the window sends it
	// back to the host waiting on that call, by the page's own spec
	mux.HandleFunc("POST /api/plugin-pages/reply", func(rw http.ResponseWriter, r *http.Request) {
		var in struct {
			Spec   string          `json:"spec"`
			CallID string          `json:"callId"`
			OK     bool            `json:"ok"`
			Result json.RawMessage `json:"result"`
			Error  string          `json:"error"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(rw, r.Body, 64<<10)).Decode(&in); err != nil {
			fail(rw, err)
			return
		}
		pages, _ := windowParts()
		found := false
		for i := range pages {
			if pages[i].Spec == in.Spec {
				found = true
				break
			}
		}
		if !found || in.CallID == "" {
			http.NotFound(rw, r)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		var out json.RawMessage
		if err := callPageInvoke(ctx, "pageReply", map[string]any{"spec": in.Spec, "id": in.CallID, "ok": in.OK, "pageReply": in.Result, "message": in.Error}, &out); err != nil {
			fail(rw, err)
			return
		}
		writeJSON(rw, map[string]bool{"ok": true})
	})
	// a background call's state, and its cancellation: only this process
	// has the job, so a magpie restart answers "no such job"
	mux.HandleFunc("GET /api/plugin-pages/jobs/{id}", func(rw http.ResponseWriter, r *http.Request) {
		out, ok := pageJobState(r.PathValue("id"))
		if !ok {
			http.NotFound(rw, r)
			return
		}
		writeJSON(rw, out)
	})
	mux.HandleFunc("POST /api/plugin-pages/jobs/{id}/cancel", func(rw http.ResponseWriter, r *http.Request) {
		if !cancelPageJob(r.PathValue("id")) {
			http.NotFound(rw, r)
			return
		}
		writeJSON(rw, map[string]bool{"ok": true})
	})
	// a page's or a panel's own options, as plugins.json keeps them: no
	// other plugin's
	mux.HandleFunc("POST /api/plugin-pages/options", func(rw http.ResponseWriter, r *http.Request) {
		var in struct {
			Spec    string          `json:"spec"`
			Options json.RawMessage `json:"options"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(rw, r.Body, 64<<10)).Decode(&in); err != nil {
			fail(rw, err)
			return
		}
		if _, _, ok := windowOf(in.Spec); !ok {
			fail(rw, errors.New("no plugin page "+in.Spec))
			return
		}
		if len(in.Options) > 0 && string(in.Options) != "null" {
			var opts map[string]any
			if err := json.Unmarshal(in.Options, &opts); err != nil {
				fail(rw, errors.New("a page's options are an object"))
				return
			}
			// a page that sets them over and over would start the
			// host, every plugin's, again each time
			if !pageSetAllowed(in.Spec, time.Now()) {
				http.Error(rw, "a page sets its options once a second at most", http.StatusTooManyRequests)
				return
			}
			if err := plugin.SetPageOptions(in.Spec, opts); err != nil {
				fail(rw, err)
				return
			}
		}
		for _, e := range plugin.Load().Plugins {
			if e.Spec == in.Spec {
				opts := e.Options
				if opts == nil {
					opts = map[string]any{}
				}
				writeJSON(rw, opts)
				return
			}
		}
		writeJSON(rw, map[string]any{})
	})
}

var pageSets = struct {
	sync.Mutex
	at map[string]time.Time
}{at: map[string]time.Time{}}

// pageSetAllowed is whether spec's page may set its options now: a second
// after it last did.
func pageSetAllowed(spec string, now time.Time) bool {
	pageSets.Lock()
	defer pageSets.Unlock()
	if last, ok := pageSets.at[spec]; ok && now.Sub(last) < time.Second {
		return false
	}
	pageSets.at[spec] = now
	return true
}

// pageRead is one of plugin.PageReads.
func pageRead(read string, params map[string]any) (any, error) {
	switch read {
	case "providers:list":
		// a name and an id each: no key, no account, no address
		type prov struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		out := []prov{}
		for _, p := range provider.All() {
			out = append(out, prov{ID: p.ID, Name: p.Name})
		}
		return out, nil
	case "usage:summary":
		period := usage.Today
		if s, _ := params["period"].(string); s != "" {
			period = usage.Period(s)
		}
		if !slices.Contains([]usage.Period{usage.Today, usage.Week, usage.Month}, period) {
			return nil, fmt.Errorf("no period %q: today, 7d or 30d", period)
		}
		s := usage.Summarize(period)
		type model struct {
			Model  string  `json:"model"`
			Calls  int     `json:"calls"`
			Input  int     `json:"input"`
			Output int     `json:"output"`
			Cost   float64 `json:"cost"`
		}
		// the totals and each model's, never a key's, an account's or a
		// session's
		out := struct {
			Period string    `json:"period"`
			Since  time.Time `json:"since"`
			Calls  int       `json:"calls"`
			Errors int       `json:"errors"`
			Input  int       `json:"input"`
			Output int       `json:"output"`
			Cache  int       `json:"cacheRead"`
			Cost   float64   `json:"cost"`
			Models []model   `json:"models"`
		}{Period: string(period), Since: s.Since, Calls: s.Calls, Errors: s.Errors, Input: s.Input, Output: s.Output, Cache: s.CacheRead, Cost: s.Cost, Models: []model{}}
		for i, g := range s.Models {
			if i == 20 {
				break
			}
			m := g.Model
			if m == "" {
				m = g.ID
			}
			out.Models = append(out.Models, model{Model: m, Calls: g.Calls, Input: g.Input, Output: g.Output, Cost: g.Cost})
		}
		return out, nil
	}
	return nil, fmt.Errorf("no read %q", read)
}
