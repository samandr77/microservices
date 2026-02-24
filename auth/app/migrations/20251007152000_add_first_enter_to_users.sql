-- +goose Up
-- +goose StatementBegin
ALTER TABLE users ADD COLUMN first_enter BOOLEAN NOT NULL DEFAULT TRUE;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE users DROP COLUMN first_enter;
-- +goose StatementEnd
