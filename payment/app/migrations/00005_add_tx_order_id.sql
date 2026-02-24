-- +goose Up
-- +goose StatementBegin
ALTER TABLE transactions ADD COLUMN order_id UUID;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE transactions DROP COLUMN order_id;
-- +goose StatementEnd
