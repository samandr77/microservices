-- +goose Up
-- +goose StatementBegin
CREATE TYPE block_type AS ENUM ('0', '1');

CREATE TABLE "user_blocks" (
    "id" UUID NOT NULL UNIQUE,
    "user_id" UUID NOT NULL UNIQUE,
    "blocked_to" TIMESTAMPTZ,
    "block_type" block_type,
    "blocks_by_period" INT NOT NULL DEFAULT 0,
    "first_block_date_by_period" TIMESTAMPTZ,
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    "updated_at" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY("id")
);

ALTER TABLE "user_blocks" ADD FOREIGN KEY("user_id") REFERENCES "users"("user_id") ON UPDATE NO ACTION ON DELETE NO ACTION;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE "user_blocks";
DROP TYPE block_type;
-- +goose StatementEnd