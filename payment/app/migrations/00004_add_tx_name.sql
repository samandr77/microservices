-- +goose Up
-- +goose StatementBegin
ALTER TABLE transactions ADD COLUMN name TEXT NOT NULL DEFAULT '';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE transactions DROP COLUMN name;
-- +goose StatementEnd
