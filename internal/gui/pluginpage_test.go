package gui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yetone/magpie/internal/plugin"
	"github.com/yetone/magpie/internal/settings"
)

// pagePlugins writes plugins.json with the example page plugin
// (testdata/page-plugin), on, and a copy of it switched off; it answers
// their specs.
func pagePlugins(t *testing.T) (on, off string) {
	t.Helper()
	h := t.TempDir()
	t.Setenv("HOME", h)
	t.Setenv("USERPROFILE", h)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(h, ".config"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(h, ".cache"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(h, ".local", "share"))
	t.Setenv("MAGPIE_BUN", "")
	t.Setenv("PATH", "")
	copyDir := func(to string) {
		t.Helper()
		err := filepath.WalkDir("testdata/page-plugin", func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel("testdata/page-plugin", p)
			if d.IsDir() {
				return os.MkdirAll(filepath.Join(to, rel), 0o755)
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			return os.WriteFile(filepath.Join(to, rel), b, 0o644)
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	on, off = filepath.Join(h, "src", "glance"), filepath.Join(h, "src", "glance-off")
	copyDir(on)
	copyDir(off)
	// a file of the plugin's own, but out of its page's folder, and one out
	// of the plugin, which a link in the page's folder points to
	if err := os.WriteFile(filepath.Join(h, "secret.txt"), []byte("SECRET"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(h, "secret.txt"), filepath.Join(on, "page", "link.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(settings.Dir(), 0o755); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]any{"plugins": []map[string]any{{"spec": on}, {"spec": off, "off": true}}})
	if err := os.WriteFile(filepath.Join(settings.Dir(), "plugins.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	return on, off
}

func pageMux() http.Handler {
	mux := http.NewServeMux()
	pluginPageRoutes(mux, false)
	mux.HandleFunc("GET /api/state", func(rw http.ResponseWriter, r *http.Request) {
		writeJSON(rw, map[string]string{"secret": "the window's"})
	})
	return noFramedAPI(mux)
}

func do(h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// A plugin's page's files are served by a token of this run, with a policy
// that keeps it to its own folder and off the network; nothing outside its
// page's folder is served, nor anything of a plugin switched off, nor
// anything by a token made up.
func TestPluginPageServedShutIn(t *testing.T) {
	on, off := pagePlugins(t)
	h := pageMux()
	var pages []pluginPage
	w := do(h, httptest.NewRequest("GET", "/api/plugin-pages", nil))
	if err := json.Unmarshal(w.Body.Bytes(), &pages); err != nil || len(pages) != 1 {
		t.Fatalf("pages: %s %v", w.Body, err)
	}
	p := pages[0]
	if p.Spec != on || p.Key != "plugin-magpie-usage-glance" || p.Title != "Usage glance" || len(p.Reads) != 1 || p.Reads[0] != "usage:summary" {
		t.Fatalf("page %+v", p)
	}
	tok := strings.Split(strings.TrimPrefix(p.URL, pluginPagePrefix), "/")[0]
	r := httptest.NewRequest("GET", p.URL, nil)
	r.Host = "127.0.0.1:3437"
	w = do(h, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Usage glance") {
		t.Fatalf("the page: %d %s", w.Code, w.Body)
	}
	csp := w.Header().Get("Content-Security-Policy")
	for _, want := range []string{"sandbox allow-scripts", "default-src 'none'", "connect-src 'none'", "script-src https://127.0.0.1:3437" + pluginPagePrefix + tok + "/ http://127.0.0.1:3437" + pluginPagePrefix + tok + "/;", "form-action 'none'", "frame-src 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("policy %q has no %q", csp, want)
		}
	}
	if strings.Contains(csp, "allow-same-origin") || strings.Contains(csp, "'unsafe-eval'") {
		t.Errorf("policy %q lets the page out", csp)
	}
	// the sandboxed frame is an origin of its own: a resource policy of
	// same-origin or same-site blocks the page's own scripts and styles
	if c := w.Header().Get("Cross-Origin-Resource-Policy"); c != "" && c != "cross-origin" {
		t.Errorf("Cross-Origin-Resource-Policy %q keeps the page from its own files", c)
	}
	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("no nosniff")
	}
	if w := do(h, httptest.NewRequest("GET", pluginPagePrefix+tok+"/"+pluginBridgePath, nil)); w.Code != 200 || !strings.Contains(w.Body.String(), "postMessage") {
		t.Errorf("the bridge: %d", w.Code)
	}
	// out of the page's folder, through a link, by another token
	for _, path := range []string{
		pluginPagePrefix + tok + "/../package.json",
		pluginPagePrefix + tok + "/link.txt",
		pluginPagePrefix + pageToken(off) + "/index.html",
		pluginPagePrefix + strings.Repeat("0", 32) + "/index.html",
		pluginPagePrefix + tok,
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.URL.Path = path
		w := httptest.NewRecorder()
		servePluginPage(w, r, false)
		if w.Code == 200 || strings.Contains(w.Body.String(), "SECRET") || strings.Contains(w.Body.String(), `"name"`) {
			t.Errorf("%s: %d %s", path, w.Code, w.Body)
		}
	}
}

// What a page didn't declare it reads is refused by the server too, not
// only by the window; a page sets its own options and no other plugin's.
func TestPluginPageReadsWhatItDeclared(t *testing.T) {
	on, off := pagePlugins(t)
	h := pageMux()
	post := func(path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		return do(h, r)
	}
	spec, _ := json.Marshal(on)
	if w := post("/api/plugin-pages/read", `{"spec":`+string(spec)+`,"read":"providers:list"}`); w.Code != http.StatusForbidden {
		t.Errorf("an undeclared read: %d %s", w.Code, w.Body)
	}
	w := post("/api/plugin-pages/read", `{"spec":`+string(spec)+`,"read":"usage:summary","params":{"period":"today"}}`)
	var sum map[string]any
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &sum) != nil || sum["period"] != "today" {
		t.Errorf("a declared read: %d %s", w.Code, w.Body)
	}
	for _, k := range []string{"callerKeys", "accounts", "sessions", "providerKeys"} {
		if _, ok := sum[k]; ok {
			t.Errorf("usage:summary gave the page %s", k)
		}
	}
	offSpec, _ := json.Marshal(off)
	if w := post("/api/plugin-pages/read", `{"spec":`+string(offSpec)+`,"read":"usage:summary"}`); w.Code == 200 {
		t.Errorf("a plugin switched off read: %d", w.Code)
	}
	if w := post("/api/plugin-pages/options", `{"spec":`+string(spec)+`,"options":{"hideCost":true}}`); w.Code != 200 || !strings.Contains(w.Body.String(), `"hideCost":true`) {
		t.Fatalf("options set: %d %s", w.Code, w.Body)
	}
	if w := post("/api/plugin-pages/options", `{"spec":`+string(spec)+`,"options":{"hideCost":false}}`); w.Code != http.StatusTooManyRequests {
		t.Errorf("a second set within the second: %d", w.Code)
	}
	if w := post("/api/plugin-pages/options", `{"spec":`+string(spec)+`}`); !strings.Contains(w.Body.String(), `"hideCost":true`) {
		t.Errorf("options get: %s", w.Body)
	}
	if w := post("/api/plugin-pages/options", `{"spec":`+string(offSpec)+`,"options":{"x":1}}`); w.Code == 200 {
		t.Errorf("another plugin's options set: %d", w.Code)
	}
	if !pageSetAllowed("x", time.Now()) || pageSetAllowed("x", time.Now()) || !pageSetAllowed("x", time.Now().Add(2*time.Second)) {
		t.Error("pageSetAllowed")
	}
}

// A page whose plugin has a part for the host too has the host up before
// its HTML is served: Magiczerowxy/magpie-chat's page sends its frame to
// the chat server that part starts, and with the host stopped (after a
// Restart, nothing else asking) WebKit left the frame on "connecting…"
// for good (guesssssssswhat on X). A page-only plugin starts no host,
// nor does any other file of the page, and a host slower than
// pageHostWait doesn't hold the page past it.
func TestPluginPageStartsItsHost(t *testing.T) {
	on, _ := pagePlugins(t)
	hosted := filepath.Join(filepath.Dir(on), "chat")
	if err := os.CopyFS(hosted, os.DirFS("testdata/page-plugin")); err != nil {
		t.Fatal(err)
	}
	pkg := `{"name": "page-chat", "main": "./index.mjs", "magpie": {"page": {"title": "Chat", "file": "page/index.html"}}}`
	if err := os.WriteFile(filepath.Join(hosted, "package.json"), []byte(pkg), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hosted, "index.mjs"), []byte("export default {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]any{"plugins": []map[string]any{{"spec": on}, {"spec": hosted}}})
	if err := os.WriteFile(filepath.Join(settings.Dir(), "plugins.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	warmed := 0
	hold := make(chan struct{})
	warmHost = func(ctx context.Context) error {
		mu.Lock()
		warmed++
		mu.Unlock()
		<-hold
		return nil
	}
	t.Cleanup(func() { warmHost = plugin.Warm })
	count := func() int {
		mu.Lock()
		defer mu.Unlock()
		return warmed
	}

	pages := pluginPages()
	if len(pages) != 2 {
		t.Fatalf("pages: %+v", pages)
	}
	glance, chat := pages[0], pages[1]
	h := pageMux()
	// the page-only plugin's page: no host
	if w := do(h, httptest.NewRequest("GET", glance.URL, nil)); w.Code != 200 || count() != 0 {
		t.Fatalf("a page-only plugin's page: %d, host started %d times", w.Code, count())
	}
	// the hosted plugin's page waits for its host
	served := make(chan *httptest.ResponseRecorder, 1)
	go func() { served <- do(h, httptest.NewRequest("GET", chat.URL, nil)) }()
	for deadline := time.Now().Add(5 * time.Second); count() == 0; {
		if time.Now().After(deadline) {
			t.Fatal("opening the hosted plugin's page didn't start its host")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case w := <-served:
		t.Fatalf("the page was served (%d) before its host was up", w.Code)
	case <-time.After(50 * time.Millisecond):
	}
	close(hold)
	if w := <-served; w.Code != 200 || !strings.Contains(w.Body.String(), "Usage glance") {
		t.Fatalf("the hosted page: %d %s", w.Code, w.Body)
	}
	// its other files ask nothing of the host
	n := count()
	tok := strings.Split(strings.TrimPrefix(chat.URL, pluginPagePrefix), "/")[0]
	for _, f := range []string{"style.css", "app.js", pluginBridgePath} {
		if w := do(h, httptest.NewRequest("GET", pluginPagePrefix+tok+"/"+f, nil)); w.Code != 200 || count() != n {
			t.Errorf("%s: %d, host started %d times", f, w.Code, count()-n)
		}
	}
	// a host that never comes up holds the page pageHostWait, no longer
	stuck := make(chan struct{})
	defer close(stuck)
	warmHost = func(ctx context.Context) error { <-stuck; return nil }
	old := pageHostWait
	pageHostWait = 100 * time.Millisecond
	t.Cleanup(func() { pageHostWait = old })
	start := time.Now()
	if w := do(h, httptest.NewRequest("GET", chat.URL, nil)); w.Code != 200 {
		t.Fatalf("the page with its host stuck: %d", w.Code)
	}
	if d := time.Since(start); d < 100*time.Millisecond || d > 3*time.Second {
		t.Errorf("the page with its host stuck waited %v; want pageHostWait (100ms)", d)
	}
}

// The desktop window's /api has no key: what keeps a plugin's page off it
// is that every way a sandboxed frame can ask is turned away, a fetch
// (Origin: null), a frame of /api, another site's page; the window's own
// requests, and a link opened from elsewhere, go on.
func TestPluginPageNoAPI(t *testing.T) {
	pagePlugins(t)
	h := pageMux()
	ask := func(set map[string]string) int {
		r := httptest.NewRequest("GET", "/api/state", nil)
		for k, v := range set {
			r.Header.Set(k, v)
		}
		return do(h, r).Code
	}
	for _, c := range []map[string]string{
		{"Origin": "null"},
		{"Origin": "null", "Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty"},
		{"Sec-Fetch-Dest": "iframe", "Sec-Fetch-Site": "same-origin"},
		{"Sec-Fetch-Dest": "image", "Sec-Fetch-Site": "cross-site"},
		{"Sec-Fetch-Dest": "script", "Sec-Fetch-Site": "cross-site"},
	} {
		if code := ask(c); code != http.StatusForbidden {
			t.Errorf("%v: %d", c, code)
		}
	}
	// the window's own handler, not only this test's
	r := httptest.NewRequest("GET", "/api/plugin-pages", nil)
	r.Header.Set("Origin", "null")
	if w := do(Handler(nil, nil), r); w.Code != http.StatusForbidden {
		t.Errorf("the window's /api to a sandboxed frame: %d", w.Code)
	}
	for _, c := range []map[string]string{
		{},
		{"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Dest": "empty", "Origin": "http://127.0.0.1:3437"},
		{"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Dest": "document"},
	} {
		if code := ask(c); code != 200 {
			t.Errorf("%v: %d", c, code)
		}
	}
}

// magpie web's guard lets a page's files through without the cookie a
// sandboxed frame never sends, and only those: a made-up token is served
// nothing, and the rest of the page still wants the key.
func TestPluginPageWebGuard(t *testing.T) {
	pagePlugins(t)
	g := webGuard("magpie_web_1", "key", 0, pageMux())
	var pages []pluginPage
	_ = json.Unmarshal(do(pageMux(), httptest.NewRequest("GET", "/api/plugin-pages", nil)).Body.Bytes(), &pages)
	if len(pages) != 1 {
		t.Fatal("no page")
	}
	if w := do(g, httptest.NewRequest("GET", pages[0].URL, nil)); w.Code != 200 {
		t.Errorf("the page's file without the cookie: %d", w.Code)
	}
	if w := do(g, httptest.NewRequest("GET", pluginPagePrefix+strings.Repeat("a", 32)+"/index.html", nil)); w.Code != 404 {
		t.Errorf("a made-up token: %d", w.Code)
	}
	if w := do(g, httptest.NewRequest("GET", "/api/plugin-pages", nil)); w.Code != http.StatusUnauthorized {
		t.Errorf("/api without the cookie: %d", w.Code)
	}
}

// A page's actions (magpie.actions) come with it to the window, one that
// names no title by the page's own in each language; a plugin switched
// off adds no item to any menu.
func TestPluginPageActions(t *testing.T) {
	on, off := pagePlugins(t)
	for _, dir := range []string{on, off} {
		pkg := `{"name":"magpie-usage-glance","magpie":{"page":{"title":"Usage glance","titles":{"zh":"用量速览"},"file":"page/index.html"},
			"actions":[{"id":"check","menu":"provider","title":"Check balance","titles":{"ja":"残高を確認"}},{"id":"logs","menu":"agent"}]}}`
		if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkg), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var pages []pluginPage
	w := do(pageMux(), httptest.NewRequest("GET", "/api/plugin-pages", nil))
	if err := json.Unmarshal(w.Body.Bytes(), &pages); err != nil || len(pages) != 1 {
		t.Fatalf("pages: %s %v", w.Body, err)
	}
	a := pages[0].Actions
	if len(a) != 2 || a[0].ID != "check" || a[0].Menu != "provider" || a[0].Title != "Check balance" || a[0].Titles["ja"] != "残高を確認" {
		t.Fatalf("actions %+v", a)
	}
	if a[1].ID != "logs" || a[1].Menu != "agent" || a[1].Title != "Usage glance" || a[1].Titles["zh"] != "用量速览" {
		t.Errorf("an action with no title: %+v, want the page's", a[1])
	}
}

// A page's methods (magpie.page.actions) come to the window with the page,
// and only those it named reach its plugin: one it didn't is refused before
// the host is asked, and the spec Go passes on is the page's own.
func TestPluginPageInvokeOnlyDeclared(t *testing.T) {
	on, _ := pagePlugins(t)
	pkg := `{"name":"magpie-usage-glance","main":"index.js","magpie":{"page":{"title":"Usage glance","file":"page/index.html","actions":["status","run"]}}}`
	if err := os.WriteFile(filepath.Join(on, "package.json"), []byte(pkg), 0o644); err != nil {
		t.Fatal(err)
	}
	var pages []pluginPage
	w := do(pageMux(), httptest.NewRequest("GET", "/api/plugin-pages", nil))
	if err := json.Unmarshal(w.Body.Bytes(), &pages); err != nil || len(pages) != 1 {
		t.Fatalf("pages: %s %v", w.Body, err)
	}
	if len(pages[0].Methods) != 2 || pages[0].Methods[0] != "status" || pages[0].Methods[1] != "run" {
		t.Fatalf("methods %v", pages[0].Methods)
	}
	old := callPageInvoke
	t.Cleanup(func() { callPageInvoke = old })
	var got map[string]any
	callPageInvoke = func(ctx context.Context, method string, params, out any) error {
		if method != "pageInvoke" {
			t.Errorf("host method %q", method)
		}
		got, _ = params.(map[string]any)
		*(out.(*json.RawMessage)) = json.RawMessage(`{"jobId":"job-1"}`)
		return nil
	}
	post := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/api/plugin-pages/invoke", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		return do(pageMux(), r)
	}
	if w := post(`{"spec":"` + on + `","method":"stop"}`); w.Code != http.StatusForbidden {
		t.Errorf("an undeclared method: %d %s", w.Code, w.Body)
	}
	if w := post(`{"spec":"` + on + `","method":"run","args":{"legs":["travel"]}}`); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"jobId":"job-1"`) {
		t.Errorf("a declared method: %d %s", w.Code, w.Body)
	}
	if got["spec"] != on || got["method"] != "run" {
		t.Errorf("passed on %v", got)
	}
	if w := post(`{"spec":"` + on + `x","method":"run"}`); w.Code != http.StatusNotFound {
		t.Errorf("an unknown page: %d", w.Code)
	}
}

// A method the page's package put in magpie.page.confirm takes a one-time
// confirmation the window got for that page, that method and those
// arguments: without it the call is refused, it can't be used twice, and
// the page's answer to a call from its plugin goes back by its spec.
func TestPluginPageConfirmAndReply(t *testing.T) {
	on, _ := pagePlugins(t)
	pkg := `{"name":"magpie-usage-glance","main":"index.js","magpie":{"page":{"title":"Usage glance","file":"page/index.html","actions":["status","run"],"confirm":["run"]}}}`
	if err := os.WriteFile(filepath.Join(on, "package.json"), []byte(pkg), 0o644); err != nil {
		t.Fatal(err)
	}
	var pages []pluginPage
	w := do(pageMux(), httptest.NewRequest("GET", "/api/plugin-pages", nil))
	if err := json.Unmarshal(w.Body.Bytes(), &pages); err != nil || len(pages) != 1 {
		t.Fatalf("pages: %s %v", w.Body, err)
	}
	if len(pages[0].Confirm) != 1 || pages[0].Confirm[0] != "run" {
		t.Fatalf("confirm %v", pages[0].Confirm)
	}
	old := callPageInvoke
	t.Cleanup(func() { callPageInvoke = old })
	var calls []map[string]any
	callPageInvoke = func(ctx context.Context, method string, params, out any) error {
		if p, ok := params.(map[string]any); ok {
			calls = append(calls, map[string]any{"method": method, "params": p})
		}
		if method == "pageInvoke" {
			*(out.(*json.RawMessage)) = json.RawMessage(`{"started":true}`)
		} else {
			*(out.(*json.RawMessage)) = json.RawMessage(`null`)
		}
		return nil
	}
	args := `{"legs":["travel"]}`
	post := func(route, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", route, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		return do(pageMux(), r)
	}
	if w := post("/api/plugin-pages/confirm", `{"spec":"`+on+`","method":"status","args":`+args+`}`); w.Code != http.StatusForbidden {
		t.Errorf("a method not confirmed: %d", w.Code)
	}
	w = post("/api/plugin-pages/confirm", `{"spec":"`+on+`","method":"run","args":`+args+`}`)
	if w.Code != http.StatusOK {
		t.Fatalf("confirm: %d %s", w.Code, w.Body)
	}
	var c struct {
		ConfirmID string `json:"confirmId"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &c); err != nil || c.ConfirmID == "" {
		t.Fatalf("confirm id: %s %v", w.Body, err)
	}
	if w := post("/api/plugin-pages/invoke", `{"spec":"`+on+`","method":"run","args":`+args+`}`); w.Code != http.StatusForbidden {
		t.Errorf("run without a confirmation: %d", w.Code)
	}
	if w := post("/api/plugin-pages/invoke", `{"spec":"`+on+`","method":"run","args":`+args+`,"confirmId":"`+c.ConfirmID+`"}`); w.Code != http.StatusOK {
		t.Errorf("run with a confirmation: %d %s", w.Code, w.Body)
	}
	if w := post("/api/plugin-pages/invoke", `{"spec":"`+on+`","method":"run","args":`+args+`,"confirmId":"`+c.ConfirmID+`"}`); w.Code != http.StatusForbidden {
		t.Errorf("the confirmation used twice: %d", w.Code)
	}
	if w := post("/api/plugin-pages/reply", `{"spec":"`+on+`","callId":"p1","ok":true,"result":{"done":true}}`); w.Code != http.StatusOK {
		t.Errorf("reply: %d %s", w.Code, w.Body)
	}
	last := calls[len(calls)-1]
	if last["method"] != "pageReply" {
		t.Errorf("reply reached %v", last)
	}
}

// A long page method runs as a job: the window gets an id at once, asks
// for its state, and may cancel it; the job's answer is kept for it.
func TestPluginPageBackgroundJob(t *testing.T) {
	on, _ := pagePlugins(t)
	pkg := `{"name":"magpie-usage-glance","main":"index.js","magpie":{"page":{"title":"Usage glance","file":"page/index.html","actions":["slow"]}}}`
	if err := os.WriteFile(filepath.Join(on, "package.json"), []byte(pkg), 0o644); err != nil {
		t.Fatal(err)
	}
	old := callPageInvoke
	t.Cleanup(func() { callPageInvoke = old })
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	callPageInvoke = func(ctx context.Context, method string, params, out any) error {
		if method != "pageInvoke" {
			return nil
		}
		started <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
			return ctx.Err()
		}
		*(out.(*json.RawMessage)) = json.RawMessage(`{"ok":true}`)
		return nil
	}
	post := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/api/plugin-pages/invoke", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		return do(pageMux(), r)
	}
	get := func(id string) *httptest.ResponseRecorder {
		return do(pageMux(), httptest.NewRequest("GET", "/api/plugin-pages/jobs/"+id, nil))
	}
	w := post(`{"spec":"` + on + `","method":"slow","background":true}`)
	if w.Code != http.StatusOK {
		t.Fatalf("background: %d %s", w.Code, w.Body)
	}
	var j struct {
		JobID string `json:"jobId"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &j); err != nil || j.JobID == "" {
		t.Fatalf("job id: %s %v", w.Body, err)
	}
	<-started
	if w := get(j.JobID); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"state":"running"`) {
		t.Errorf("running: %d %s", w.Code, w.Body)
	}
	close(release)
	for i := 0; i < 100; i++ {
		w = get(j.JobID)
		if strings.Contains(w.Body.String(), `"state":"done"`) && strings.Contains(w.Body.String(), `"ok":true`) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("the job never finished: %s", w.Body)
}
