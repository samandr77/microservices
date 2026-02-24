-- +goose Up
-- +goose StatementBegin
INSERT INTO roles (id, role_name) VALUES
    (gen_random_uuid(), 'donor'),
    (gen_random_uuid(), 'board_member'),
    (gen_random_uuid(), 'npo'),
    (gen_random_uuid(), 'content_manager'),
    (gen_random_uuid(), 'client_manager'),
    (gen_random_uuid(), 'support_employee'),
    (gen_random_uuid(), 'technical_admin'),
    (gen_random_uuid(), 'business_admin');
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DELETE FROM roles WHERE role_name IN (
    'donor',
    'board_member', 
    'npo',
    'content_manager',
    'client_manager',
    'support_employee',
    'technical_admin',
    'business_admin'
);
-- +goose StatementEnd