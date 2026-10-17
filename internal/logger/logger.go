package logger

import (
	"context"
	"log/slog"
	"os"
	"strings"
)

var sensitiveKeys = map[string]bool{
	"password":         true,
	"current_password": true,
	"new_password":     true,
	"token":            true,
	"access_token":     true,
	"refresh_token":    true,
	"otp":              true,
	"authorization":    true,
	"jwt_secret":       true,
	"redis_password":   true,
}

type MaskingHandler struct {
	slog.Handler
}

func NewMaskingHandler(h slog.Handler) *MaskingHandler {
	return &MaskingHandler{Handler: h}
}

func (m *MaskingHandler) Handle(ctx context.Context, r slog.Record) error {
	newRecord := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	r.Attrs(func(a slog.Attr) bool {
		newRecord.AddAttrs(maskAttr(a))
		return true
	})
	return m.Handler.Handle(ctx, newRecord)
}

func maskAttr(a slog.Attr) slog.Attr {
	keyLower := strings.ToLower(a.Key)
	if sensitiveKeys[keyLower] {
		return slog.String(a.Key, "[REDACTED]")
	}
	if a.Value.Kind() == slog.KindGroup {
		attrs := a.Value.Group()
		masked := make([]slog.Attr, len(attrs))
		for i, attr := range attrs {
			masked[i] = maskAttr(attr)
		}
		return slog.Group(a.Key, anySlice(masked)...)
	}
	return a
}

func anySlice(attrs []slog.Attr) []any {
	anys := make([]any, len(attrs))
	for i, a := range attrs {
		anys[i] = a
	}
	return anys
}

func New(isProduction bool) *slog.Logger {
	opts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}

	var baseHandler slog.Handler
	if isProduction {
		baseHandler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		baseHandler = slog.NewTextHandler(os.Stdout, opts)
	}

	maskingHandler := NewMaskingHandler(baseHandler)
	return slog.New(maskingHandler)
}

// Audit logs security audit events in a structured format
func Audit(ctx context.Context, logger *slog.Logger, event string, args ...any) {
	if logger == nil {
		return
	}
	allArgs := append([]any{slog.Bool("audit_event", true), slog.String("event", event)}, args...)
	logger.InfoContext(ctx, "SECURITY_AUDIT: "+event, allArgs...)
}
