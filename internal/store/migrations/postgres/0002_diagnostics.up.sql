ALTER TABLE messages ADD COLUMN origin TEXT NOT NULL DEFAULT 'smtp' CHECK (origin IN ('smtp', 'diagnostic'));
CREATE TABLE diagnostic_requests (
 actor_id TEXT NOT NULL,
 request_id TEXT NOT NULL,
 mailbox_id TEXT NOT NULL,
 recipient TEXT NOT NULL,
 message_id TEXT REFERENCES messages(id) ON DELETE SET NULL,
 created_at TIMESTAMPTZ NOT NULL,
 PRIMARY KEY (actor_id, request_id)
);
