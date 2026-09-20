package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/davidgroves/dnssec-auditor/internal/dnssec"
	"github.com/davidgroves/dnssec-auditor/internal/event"
)

func (s *Server) dumpZone(ctx context.Context, input *zonePathInput) (*huma.StreamResponse, error) {
	z, err := s.zoneOrNotFound(input.Zone)
	if err != nil {
		return nil, err
	}
	st, findings := z.StoreAndFindings()
	if st == nil {
		return nil, huma.Error409Conflict("no zone data")
	}
	comments := dnssec.ErrorCommentsByOwner(findings)
	filename := strings.TrimSuffix(st.Origin(), ".") + ".txt"
	return &huma.StreamResponse{
		Body: func(hctx huma.Context) {
			hctx.SetHeader("Content-Type", "text/plain; charset=utf-8")
			hctx.SetHeader("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
			_ = st.WriteZoneFileAnnotated(hctx.BodyWriter(), comments)
		},
	}, nil
}

// exportZone is the historical path; same dump as /dump.
func (s *Server) exportZone(ctx context.Context, input *zonePathInput) (*huma.StreamResponse, error) {
	return s.dumpZone(ctx, input)
}

func (s *Server) streamEvents(ctx context.Context, _ *struct{}) (*huma.StreamResponse, error) {
	ch := make(chan event.Event, 32)
	s.sseMu.Lock()
	s.sse[ch] = struct{}{}
	s.sseMu.Unlock()

	return &huma.StreamResponse{
		Body: func(hctx huma.Context) {
			defer func() {
				s.sseMu.Lock()
				delete(s.sse, ch)
				s.sseMu.Unlock()
			}()

			hctx.SetHeader("Content-Type", "text/event-stream")
			hctx.SetHeader("Cache-Control", "no-cache")
			hctx.SetHeader("Connection", "keep-alive")

			w := hctx.BodyWriter()
			fl, ok := w.(http.Flusher)
			if !ok {
				return
			}

			reqCtx := hctx.Context()
			for {
				select {
				case <-reqCtx.Done():
					return
				case e := <-ch:
					b, _ := json.Marshal(e)
					_, _ = w.Write([]byte("data: "))
					_, _ = w.Write(b)
					_, _ = w.Write([]byte("\n\n"))
					fl.Flush()
				}
			}
		},
	}, nil
}
