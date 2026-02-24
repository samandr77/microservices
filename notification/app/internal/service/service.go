package service

import (
	"fmt"

	"github.com/samandr77/microservices/notification/internal/clients/gomail"
	"github.com/samandr77/microservices/notification/internal/entity"
	"github.com/samandr77/microservices/notification/pkg/config"
)

type Service struct {
	cfg          config.Config
	gomailClient *gomail.Client
}

func New(cfg config.Config, gomailClient *gomail.Client) *Service {
	return &Service{
		cfg:          cfg,
		gomailClient: gomailClient,
	}
}

func (s *Service) SendMessage(message entity.Message) error {
	switch message.Type {
	case "email":
		err := s.gomailClient.SendMessage(
			message.Subject,
			message.Message,
			message.Recipients,
			message.ContentType,
		)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("%w: %s", entity.ErrUnknownMessageType, message.Type)
	}

	return nil
}
