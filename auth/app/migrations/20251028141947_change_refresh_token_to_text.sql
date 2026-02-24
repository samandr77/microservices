-- +goose Up
-- +goose StatementBegin
ALTER TABLE token ALTER COLUMN refresh_token TYPE TEXT;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE token ALTER COLUMN refresh_token TYPE VARCHAR(255);
-- +goose StatementEnd
