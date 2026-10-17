package email

import (
	"bytes"
	"fmt"
	"html/template"
	"path/filepath"
	"time"
)

type Renderer struct {
	templateMap map[string]*template.Template
}

func NewRenderer(templatesDir string) (*Renderer, error) {
	basePath := filepath.Join(templatesDir, "base.html")
	files, err := filepath.Glob(filepath.Join(templatesDir, "*.html"))
	if err != nil {
		return nil, fmt.Errorf("failed to glob email templates: %w", err)
	}

	r := &Renderer{
		templateMap: make(map[string]*template.Template),
	}

	for _, file := range files {
		name := filepath.Base(file)
		if name == "base.html" {
			continue
		}

		tmpl, err := template.ParseFiles(basePath, file)
		if err != nil {
			return nil, fmt.Errorf("failed to parse template %s: %w", name, err)
		}
		r.templateMap[name] = tmpl
	}

	return r, nil
}

func (r *Renderer) Render(templateName string, data any) (string, error) {
	tmpl, ok := r.templateMap[templateName]
	if !ok {
		return "", fmt.Errorf("template %s not found", templateName)
	}

	var buf bytes.Buffer
	meta := r.enrichData(data)

	err := tmpl.ExecuteTemplate(&buf, templateName, meta)
	if err != nil {
		return "", fmt.Errorf("failed to render template %s: %w", templateName, err)
	}

	return buf.String(), nil
}

func (r *Renderer) enrichData(data any) any {
	if m, ok := data.(map[string]any); ok {
		if _, exists := m["Year"]; !exists {
			m["Year"] = time.Now().Year()
		}
		return m
	}

	return data
}
