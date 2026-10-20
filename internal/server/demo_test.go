package server

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func TestDemoModesCannotExecute(t *testing.T) {
	var static fs.FS = fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("demo")}}
	h := New(Config{Static: static})
	for _, mode := range []string{"dir", "tool"} {
		t.Run(mode, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/api/scan", strings.NewReader(`{"mode":"`+mode+`","dir":{"baseUrl":"http://127.0.0.1:9"},"tool":{"tool":"nikto","target":"http://127.0.0.1:9"}}`))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != http.StatusForbidden {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			var body map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if body["id"] != nil || body["error"] == nil {
				t.Fatalf("unexpected response: %v", body)
			}
		})
	}
}

func TestToolPreviewDisabled(t *testing.T) {
	h := New(Config{Static: fstest.MapFS{}})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/tools/preview", strings.NewReader(`{"tool":"nikto","target":"http://127.0.0.1:9"}`)))
	if w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), `"command"`) {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestDemoEndpointsStillRequireToken(t *testing.T) {
	h := New(Config{Static: fstest.MapFS{}, Token: "test-token"})
	for _, path := range []string{"/api/scan", "/api/tools/preview"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"mode":"dir"}`)))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("%s status=%d", path, w.Code)
		}
		w = httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"mode":"dir"}`))
		r.Header.Set("X-Token", "test-token")
		h.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("%s authorized status=%d", path, w.Code)
		}
	}
}
