CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT NOT NULL PRIMARY KEY,
    data TEXT NOT NULL DEFAULT '',
    ip TEXT NOT NULL DEFAULT '',
    agent TEXT NOT NULL DEFAULT '',
    stamp INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_sessions_stamp ON sessions (stamp);
