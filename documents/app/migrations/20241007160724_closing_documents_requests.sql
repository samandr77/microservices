-- +goose Up
-- +goose StatementBegin
CREATE TABLE closing_documents_requests (
id uuid PRIMARY KEY,
client_id uuid NOT NULL,
client_name text NOT NULL,
status text NOT NULL,
one_c_guid uuid NOT NULL,
created_at timestamptz NOT NULL,
updated_at timestamptz NOT NULL
);

-- +goose StatementEnd
-- +goose Down
-- +goose StatementBegin
DROP TABLE closing_documents_requests;

-- +goose StatementEnd
