-- +goose Up
-- +goose StatementBegin
ALTER TABLE transactions ADD COLUMN invoice_url TEXT;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE transactions DROP COLUMN invoice_url;
-- +goose StatementEnd
