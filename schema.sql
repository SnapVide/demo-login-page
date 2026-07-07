CREATE TABLE login_attempts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE code_attempts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  login_attempt_id INTEGER,
  username TEXT,
  code_hash TEXT NOT NULL,
  code_salt TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);