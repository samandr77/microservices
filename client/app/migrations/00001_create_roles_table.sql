-- +goose Up
-- +goose StatementBegin
CREATE TABLE "roles" (
    "id" UUID NOT NULL UNIQUE,
    "role_name" VARCHAR NOT NULL,
    PRIMARY KEY("id")
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE "roles";
-- +goose StatementEnd