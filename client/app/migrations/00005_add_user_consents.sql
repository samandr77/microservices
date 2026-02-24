-- +goose Up
-- +goose StatementBegin
ALTER TABLE users
ADD COLUMN privacy_policy_agreed BOOLEAN NOT NULL DEFAULT FALSE,
ADD COLUMN newsletter_agreed BOOLEAN DEFAULT FALSE,
ADD COLUMN public_donations_agreed BOOLEAN DEFAULT FALSE;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE users
DROP COLUMN privacy_policy_agreed,
DROP COLUMN newsletter_agreed,
DROP COLUMN public_donations_agreed;
-- +goose StatementEnd
