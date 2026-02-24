-- +goose Up
-- +goose StatementBegin
ALTER TABLE users
    ALTER COLUMN sub TYPE VARCHAR(96) USING sub::text,
    ALTER COLUMN sub_alt TYPE VARCHAR(96) USING sub_alt::text;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE users
    ALTER COLUMN sub TYPE UUID USING sub::uuid,
    ALTER COLUMN sub_alt TYPE UUID USING sub_alt::uuid;
-- +goose StatementEnd
