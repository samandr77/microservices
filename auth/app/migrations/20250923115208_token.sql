-- +goose Up
-- +goose StatementBegin
CREATE TABLE token (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    is_used BOOLEAN NOT NULL DEFAULT FALSE,
    user_id UUID NOT NULL,
    refresh_token VARCHAR(255) NOT NULL,
    refresh_token_expire INTEGER NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE token;
-- +goose StatementEnd
