package email

import (
	"fmt"
	"net/smtp"
)

type Provider interface {
	Send(to, subject, body string) error
}

type SMTPProvider struct {
	host     string
	port     string
	username string
	password string
	from     string
}

func NewSMTPProvider(host, port, username, password, from string) *SMTPProvider {
	return &SMTPProvider{
		host:     host,
		port:     port,
		username: username,
		password: password,
		from:     from,
	}
}

func (p *SMTPProvider) Send(to, subject, body string) error {
	auth := smtp.PlainAuth("", p.username, p.password, p.host)

	msg := []byte(fmt.Sprintf("From: %s\r\n"+
		"To: %s\r\n"+
		"Subject: %s\r\n"+
		"Content-Type: text/html; charset=UTF-8\r\n"+
		"\r\n"+
		"%s\r\n", p.from, to, subject, body))

	addr := fmt.Sprintf("%s:%s", p.host, p.port)
	return smtp.SendMail(addr, auth, p.from, []string{to}, msg)
}

type MockProvider struct{}

func (p *MockProvider) Send(to, subject, body string) error {
	fmt.Printf("\n--- MOCK EMAIL SENT ---\nTo: %s\nSubject: %s\nBody: %s\n-----------------------\n", to, subject, body)
	return nil
}
