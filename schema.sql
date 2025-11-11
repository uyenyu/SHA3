PRAGMA foreign_keys = ON;

/* Bảng admins cũ đã bị XÓA */
DROP TABLE IF EXISTS admins;

/* TẠO BẢNG MỚI (hoặc cập nhật): organizations */
CREATE TABLE IF NOT EXISTS organizations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    address TEXT,
    manager_user_id INTEGER,
    FOREIGN KEY (manager_user_id) REFERENCES users (id) ON DELETE SET NULL
);

/* CẬP NHẬT BẢNG "users" (Bảng duy nhất cho mọi người) */
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cccd TEXT UNIQUE,
    username TEXT UNIQUE, /* Superadmin dùng cái này */
    full_name TEXT NOT NULL,
    dob TEXT,
    email TEXT UNIQUE,
    gender TEXT,
    phone TEXT,
    address TEXT,
    organization_id INTEGER,
    password_hash TEXT NOT NULL,
    user_hash TEXT UNIQUE NOT NULL,
    avatar_url TEXT,
    role TEXT NOT NULL DEFAULT 'user', /* 'user', 'admin', 'superadmin' */
    registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (organization_id) REFERENCES organizations (id) ON DELETE SET NULL
);

/* Bảng elections (cập nhật khóa ngoại) */
CREATE TABLE IF NOT EXISTS elections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    organization_id INTEGER,
    start_date TEXT NOT NULL,
    end_date TEXT NOT NULL,
    election_code TEXT UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (organization_id) REFERENCES organizations (id) ON DELETE SET NULL
);

/* Bảng election_candidates (không đổi) */
CREATE TABLE IF NOT EXISTS election_candidates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    election_id INTEGER NOT NULL,
    description TEXT,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    FOREIGN KEY (election_id) REFERENCES elections (id) ON DELETE CASCADE,
    UNIQUE (user_id, election_id)
);

/* Bảng votes (không đổi) */
CREATE TABLE IF NOT EXISTS votes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    election_id INTEGER NOT NULL,
    voted_for_user_id INTEGER NOT NULL,
    voted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    vote_hash TEXT NOT NULL,
    vote_data TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    FOREIGN KEY (election_id) REFERENCES elections (id) ON DELETE CASCADE,
    FOREIGN KEY (voted_for_user_id) REFERENCES users (id) ON DELETE CASCADE,
    UNIQUE (user_id, election_id)
);