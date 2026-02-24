-- +goose Up
-- +goose StatementBegin
CREATE TYPE user_status AS ENUM ('active', 'blocked', 'deleted');
CREATE TYPE verification_status AS ENUM ('unverified', 'pending', 'verified');

CREATE TABLE "users" (
    "user_id" UUID NOT NULL UNIQUE,
    "sub" UUID UNIQUE,
    "sub_alt" UUID UNIQUE,
    "last_name" VARCHAR,
    "first_name" VARCHAR,
    "middle_name" VARCHAR,
    "email" VARCHAR NOT NULL,
    "phone" VARCHAR,
    "birthdate" DATE,
    "city" VARCHAR,
    "school_name" VARCHAR,
    "place_of_education" VARCHAR,
    "address_reg" VARCHAR,
    "series" VARCHAR,
    "number" VARCHAR,
    "issued_by" VARCHAR,
    "issued_date" DATE,
    "code" VARCHAR,
    "personal_info" VARCHAR(255),
    "role_id" UUID NOT NULL,
    "status" user_status NOT NULL,
    "verification_status" verification_status NOT NULL,
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    "updated_at" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    "deleted_at" TIMESTAMPTZ,
    PRIMARY KEY("user_id")
);

ALTER TABLE "users" ADD FOREIGN KEY("role_id") REFERENCES "roles"("id") ON UPDATE NO ACTION ON DELETE NO ACTION;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE "users";
DROP TYPE verification_status;
DROP TYPE user_status;
-- +goose StatementEnd