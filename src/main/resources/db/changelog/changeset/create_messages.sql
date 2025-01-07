CREATE TABLE messages
(
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT REFERENCES app_users(id),
    content VARCHAR(128) NOT NULL,
    created_at DATE DEFAULT CURRENT_DATE
)