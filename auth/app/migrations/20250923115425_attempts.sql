-- +goose Up
-- +goose StatementBegin
CREATE TYPE attempt_type AS ENUM ('auth', 'register');
CREATE TYPE provider_type AS ENUM ('sber_id', 'email');

CREATE TABLE attempts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    type attempt_type NOT NULL,
    user_id UUID NULL,
    provider provider_type NOT NULL,
    email VARCHAR(255) NOT NULL,
    ip_address VARCHAR(255) NOT NULL,
    code_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE attempts;
DROP TYPE attempt_type;
DROP TYPE provider_type;
-- +goose StatementEnd
