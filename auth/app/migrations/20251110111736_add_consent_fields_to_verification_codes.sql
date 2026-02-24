-- +goose Up
-- +goose StatementBegin
ALTER TABLE verification_codes
ADD COLUMN privacy_policy_agreed BOOLEAN DEFAULT NULL,
ADD COLUMN newsletter_agreed BOOLEAN DEFAULT FALSE,
ADD COLUMN public_donations_agreed BOOLEAN DEFAULT FALSE;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE verification_codes
DROP COLUMN privacy_policy_agreed,
DROP COLUMN newsletter_agreed,
DROP COLUMN public_donations_agreed;
-- +goose StatementEnd
