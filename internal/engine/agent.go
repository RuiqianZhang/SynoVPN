package engine

import (
	"encoding/json"
	"net/http"
	"synovpn/internal/pki"
)

func AgentHandler(e Engine) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /revoke", func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			ID string `json:"id"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&request) != nil || !IDPattern.MatchString(request.ID) {
			http.Error(w, "invalid device", 400)
			return
		}
		status, err := e.Revoke(r.Context(), request.ID)
		agentReply(w, status, err)
	})
	mux.HandleFunc("POST /issue", func(w http.ResponseWriter, r *http.Request) {
		var request pki.IssueRequest
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&request) != nil {
			http.Error(w, "invalid request", 400)
			return
		}
		issued, err := e.Issue(r.Context(), request)
		if err != nil {
			http.Error(w, "certificate issuance rejected", 409)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(issued)
	})
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) { s, err := e.Status(r.Context()); agentReply(w, s, err) })
	mux.HandleFunc("POST /sync", func(w http.ResponseWriter, r *http.Request) {
		var ds []Device
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<20))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&ds) != nil || Validate(ds) != nil {
			http.Error(w, "invalid snapshot", 400)
			return
		}
		s, err := e.Sync(r.Context(), ds)
		agentReply(w, s, err)
	})
	return mux
}
func agentReply(w http.ResponseWriter, s Status, e error) {
	w.Header().Set("Content-Type", "application/json")
	if e != nil {
		s.Ready = false
		s.Error = "VPN 引擎尚未就绪，操作将自动重试"
		w.WriteHeader(503)
	}
	json.NewEncoder(w).Encode(s)
}
