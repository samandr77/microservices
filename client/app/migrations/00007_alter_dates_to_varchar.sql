-- +goose Up
-- +goose StatementBegin
ALTER TABLE users 
    ALTER COLUMN birthdate TYPE VARCHAR USING TO_CHAR(birthdate, 'DD.MM.YYYY'),
    ALTER COLUMN issued_date TYPE VARCHAR USING TO_CHAR(issued_date, 'DD.MM.YYYY');
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE users 
    ALTER COLUMN birthdate TYPE DATE USING TO_DATE(birthdate, 'DD.MM.YYYY'),
    ALTER COLUMN issued_date TYPE DATE USING TO_DATE(issued_date, 'DD.MM.YYYY');
-- +goose StatementEnd

