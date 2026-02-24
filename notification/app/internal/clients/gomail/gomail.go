package gomail

import (
	"crypto/tls"
	"fmt"
	"regexp"

	"github.com/samandr77/microservices/notification/pkg/config"
	"gopkg.in/gomail.v2"
)

type Client struct {
	cfg    config.Config
	dialer *gomail.Dialer
}

func New(cfg config.Config) *Client {
	dialer := gomail.NewDialer(cfg.MailerHost, cfg.MailerPort, cfg.MailerLogin, cfg.MailerPassword)

	dialer.TLSConfig = &tls.Config{
		ServerName: cfg.MailerHost,
		MinVersion: tls.VersionTLS12,
	}

	return &Client{
		cfg:    cfg,
		dialer: dialer,
	}
}

func (c *Client) SendMessage(subject, message string, recipients []string, contentType string) error {
	msg := gomail.NewMessage(
		gomail.SetCharset("UTF-8"),
		gomail.SetEncoding(gomail.Base64),
	)

	msg.SetAddressHeader("From", c.cfg.MailerFrom, c.cfg.MailerFromName)
	msg.SetHeader("To", recipients...)
	msg.SetHeader("Subject", subject)

	switch contentType {
	case "text/html":
		msg.SetBody("text/html", message)
	case "text/plain":
		msg.SetBody("text/plain", message)
	default:
		if isHTML(message) {
			msg.SetBody("text/html", message)
		} else {
			msg.SetBody("text/plain", message)
		}
	}

	err := c.dialer.DialAndSend(msg)
	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}

func isHTML(message string) bool {
	return regexp.MustCompile("<[^>]+>").MatchString(message)
}
