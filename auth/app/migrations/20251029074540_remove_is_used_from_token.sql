-- +goose Up
-- +goose StatementBegin
ALTER TABLE token DROP COLUMN IF EXISTS is_used;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE token ADD COLUMN is_used BOOLEAN NOT NULL DEFAULT FALSE;
-- +goose StatementEnd
