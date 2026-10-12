import random, string
from faker import Faker
from stdnum import verhoeff
from stdnum.in_ import pan as stdpan

fake = Faker("en_IN")

def aadhaar():
    base = str(random.randint(2, 9)) + "".join(random.choices(string.digits, k=10))
    return base + verhoeff.calc_check_digit(base)

def pan():
    while True:
        c = ("".join(random.choices(string.ascii_uppercase, k=3)) + random.choice("PCHFATBLJG")
             + random.choice(string.ascii_uppercase) + "".join(random.choices(string.digits, k=4))
             + random.choice(string.ascii_uppercase))
        if stdpan.is_valid(c):
            return c

def ssn():
    return f"{random.randint(100, 899)}-{random.randint(10, 99)}-{random.randint(1000, 9999)}"

def make_db(conn, n=300, seed=7):
    random.seed(seed); Faker.seed(seed); fake.unique.clear()
    conn.executescript("""
        CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT, phone TEXT, aadhaar TEXT, pan TEXT,
                            ssn TEXT, city TEXT);
        CREATE TABLE accounts (id INTEGER PRIMARY KEY, user_id INTEGER, credit_card TEXT, iban TEXT,
                               balance REAL, status TEXT);""")
    for i in range(1, n + 1):
        conn.execute("INSERT INTO users VALUES (?,?,?,?,?,?,?,?)",
                     (i, fake.name(), fake.unique.email(), "9" + "".join(random.choices(string.digits, k=9)),
                      aadhaar(), pan(), ssn(), fake.city()))
        conn.execute("INSERT INTO accounts VALUES (?,?,?,?,?,?)",
                     (i, i, fake.credit_card_number(), fake.iban(), round(random.uniform(0, 900000), 2),
                      random.choice(["active", "frozen"])))
    conn.commit()
