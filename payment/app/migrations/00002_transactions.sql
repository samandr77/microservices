-- +goose Up
-- +goose StatementBegin
CREATE TABLE transactions
(
	id               uuid PRIMARY KEY,
	number           BIGINT GENERATED ALWAYS AS IDENTITY UNIQUE,
	client_id        uuid           NOT NULL,
	client_guid      uuid           NOT NULL,
	amount           NUMERIC(20, 2) NOT NULL,
	payment_method   TEXT           NOT NULL,
	status           TEXT           NOT NULL,
	created_by       uuid           NOT NULL,
	created_at       timestamptz    NOT NULL,
	updated_at       timestamptz    NOT NULL
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE transactions;
-- +goose StatementEnd
