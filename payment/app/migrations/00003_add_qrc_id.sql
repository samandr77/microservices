-- +goose Up
-- +goose StatementBegin
ALTER TABLE transactions ADD COLUMN qrc_id TEXT;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE transactions DROP COLUMN qrc_id;
-- +goose StatementEnd
