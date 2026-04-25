package email

import (
	"bytes"
	"fmt"
	"html/template"
	"path/filepath"
	"time"
)

// Renderer handles the loading and rendering of HTML templates.
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

		// Each page template is parsed with the base template to create a unique template set.
		// This prevents "define" blocks like "content" from overwriting each other.
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

	// Execute the specific page template (its name is the filename)
	err := tmpl.ExecuteTemplate(&buf, templateName, meta)
	if err != nil {
		return "", fmt.Errorf("failed to render template %s: %w", templateName, err)
	}

	return buf.String(), nil
}

func (r *Renderer) enrichData(data any) any {
	// If data is a map, add common fields
	if m, ok := data.(map[string]any); ok {
		if _, exists := m["Year"]; !exists {
			m["Year"] = time.Now().Year()
		}
		return m
	}

	// If it's a struct, we'd need reflection or just wrap it.
	// For simplicity in this template, we'll assume maps or specific DTOs are used.
	return data
}
