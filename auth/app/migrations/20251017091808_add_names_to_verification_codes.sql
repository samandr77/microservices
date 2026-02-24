-- +goose Up
-- +goose StatementBegin
ALTER TABLE verification_codes
ADD COLUMN first_name VARCHAR(255) DEFAULT NULL,
ADD COLUMN last_name VARCHAR(255) DEFAULT NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE verification_codes
DROP COLUMN first_name,
DROP COLUMN last_name;
-- +goose StatementEnd
