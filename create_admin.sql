-- Create Admin User Script
-- Run this in your PostgreSQL database to create an admin user

-- First, let's check if the users table exists
SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_name='users';

-- Create an admin user (replace 'admin@example.com' and 'adminname' with desired values)
INSERT INTO users (id, name, email, password_hash, role, quota_limit, quota_used, is_active, created_at, updated_at) 
VALUES (
    gen_random_uuid(),
    'System Administrator',
    'admin@balkanid.com',
    '$2a$10$K.8YNS7D5FJ8rD7SHbJQH.JM1kL5dRB4.K0F8.8YbH8oC3yZ9K1zC', -- bcrypt hash for 'admin123'
    'ADMIN',
    1073741824, -- 1GB quota (1024*1024*1024 bytes)
    0,          -- No storage used initially
    true,       -- Active user
    NOW(),
    NOW()
) ON CONFLICT (email) DO UPDATE SET
    role = 'ADMIN',
    name = 'System Administrator';

-- Verify the admin user was created
SELECT id, name, email, role, quota_limit, is_active, created_at 
FROM users 
WHERE role = 'ADMIN';

-- Note: The password hash above corresponds to 'admin123'
-- You can generate a new hash using: 
-- https://bcrypt-generator.com/ with cost 10
-- Or use Go: golang.org/x/crypto/bcrypt.GenerateFromPassword([]byte("yourpassword"), 10)