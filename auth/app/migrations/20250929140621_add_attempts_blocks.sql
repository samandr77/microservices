-- +goose Up
-- +goose StatementBegin
CREATE TABLE attempts_blocks (
  id UUID NOT NULL,
  email VARCHAR(255) NOT NULL,
  ip_address VARCHAR(255) NOT NULL,
  start_block TIMESTAMPTZ NOT NULL,
  end_block TIMESTAMPTZ NOT NULL,
  type VARCHAR(50) NOT NULL DEFAULT 'signup'
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE attempts_blocks;
-- +goose StatementEnd
