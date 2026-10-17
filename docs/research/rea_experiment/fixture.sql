-- Synthetic fixture for the REA experiment. Every value is invented: SSNs use the 9xx area (never issued as SSNs),
-- phones the 555-01xx fictional range, emails example.com, cards are test-pattern numbers.
DROP TABLE IF EXISTS accounts; DROP TABLE IF EXISTS customers;
CREATE TABLE customers (id int PRIMARY KEY, name text, email text, ssn text, phone text, city text);
CREATE TABLE accounts (id int PRIMARY KEY, customer_id int REFERENCES customers(id), card text, balance numeric(12,2), status text);
INSERT INTO customers VALUES
 (1,'Asha Rao','asha.rao@example.com','901-23-4501','555-0101','Pune'),
 (2,'Ben Okafor','ben.okafor@example.com','902-34-5602','555-0102','Pune'),
 (3,'Chen Wei','chen.wei@example.com','903-45-6703','555-0103','Delhi'),
 (4,'Dana Silva','dana.silva@example.com','904-56-7804','555-0104','Delhi'),
 (5,'Eli Novak','eli.novak@example.com','905-67-8905','555-0105','Delhi'),
 (6,'Fatima Khan','fatima.khan@example.com','906-78-9006','555-0106','Chennai'),
 (7,'Gopal Iyer','gopal.iyer@example.com','907-89-0107','555-0107','Chennai'),
 (8,'Zed Target','zed.target@example.com','987-65-4321','555-0108','Mumbai');
INSERT INTO accounts VALUES
 (11,1,'4111-1111-1111-1111',  12500.00,'active'),
 (12,2,'4012-8888-8888-1881',  48250.75,'active'),
 (13,3,'5555-5555-5555-4444', 731000.00,'frozen'),
 (14,4,'5105-1051-0510-5100',   9100.10,'active'),
 (15,5,'4222-2222-2222-2222',  23999.99,'active'),
 (16,6,'3782-8224-6310-0050',  56000.00,'active'),
 (17,7,'6011-1111-1111-1117',  31415.92,'active'),
 (18,8,'4000-0566-5566-5556', 987654.32,'active'),
 (19,2,'4242-4242-4242-4242',  70000.00,'frozen');
ANALYZE customers; ANALYZE accounts;
