-- Schema of MaskGuard's demo bank (the same SQL runs on SQLite, PostgreSQL and MySQL).
-- Loaded by src/maskguard/seed.py, which then fills it with synthetic data for a fixed seed.
-- MaskGuard itself stores nothing in the customer's database: this is demo data only.
DROP TABLE IF EXISTS support_tickets;
DROP TABLE IF EXISTS accounts;
DROP TABLE IF EXISTS users;
CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT, phone TEXT, aadhaar TEXT, pan TEXT,
                    ssn TEXT, city TEXT);
CREATE TABLE accounts (id INTEGER PRIMARY KEY, user_id INTEGER, credit_card TEXT, iban TEXT,
                       balance NUMERIC(12,2), status TEXT);
-- support_tickets hides personal data behind non-obvious names: contact holds phones, payment_ref card numbers,
-- order_ref 12-digit numbers that fail the Aadhaar check (a decoy the scanner must leave alone).
CREATE TABLE support_tickets (id INTEGER PRIMARY KEY, user_id INTEGER, contact TEXT, payment_ref TEXT,
                              order_ref TEXT, notes TEXT, status TEXT, message TEXT);
