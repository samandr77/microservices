-- +goose Up
-- +goose StatementBegin
CREATE TABLE documents (
    id uuid PRIMARY KEY,
    client_id uuid NOT NULL,
    client_name text,
    name text NOT NULL,
    doc_type text NOT NULL,
    status text NOT NULL,
    created_at timestamptz NOT NULL,
    signed_at timestamptz,
    sum decimal(10, 2),
    url text,
    data jsonb,
    one_c_guid uuid
);

-- +goose StatementEnd
-- +goose Down
-- +goose StatementBegin
DROP TABLE documents;

-- +goose StatementEnd
