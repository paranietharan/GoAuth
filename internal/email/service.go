package email

import (
	"fmt"
	"net/smtp"
)

type Service struct {
	host     string
	port     string
	username string
	password string
	from     string
}

func NewService(host, port, username, password, from string) *Service {
	return &Service{
		host:     host,
		port:     port,
		username: username,
		password: password,
		from:     from,
	}
}

func (s *Service) SendEmail(to, subject, body string) error {
	auth := smtp.PlainAuth("", s.username, s.password, s.host)

	msg := []byte(fmt.Sprintf("From: %s\r\n"+
		"To: %s\r\n"+
		"Subject: %s\r\n"+
		"Content-Type: text/html; charset=UTF-8\r\n"+
		"\r\n"+
		"%s\r\n", s.from, to, subject, body))

	fmt.Printf("%s\n%s\n", subject, body)
	addr := fmt.Sprintf("%s:%s", s.host, s.port)
	return smtp.SendMail(addr, auth, s.from, []string{to}, msg)
}
