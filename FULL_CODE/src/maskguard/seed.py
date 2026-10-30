"""Synthetic bank data, identical on SQLite and PostgreSQL for the same seed.

support_tickets deliberately hides PII behind non-obvious headers (contact = phone, payment_ref = card) and adds
order_ref, 12-digit numbers that fail the Aadhaar checksum, to check the scanner relies on values, not names.
"""

import random
import string
from importlib.resources import files

from faker import Faker
from stdnum import verhoeff
from stdnum.in_ import pan as stdpan

fake = Faker("en_IN")
fake_gb = Faker("en_GB")  # India has no IBAN; use a country whose IBANs validate

DDL = files("maskguard").joinpath("db/schema.sql").read_text(encoding="utf-8")  # the demo schema, as SQL


def aadhaar():
    base = str(random.randint(2, 9)) + "".join(random.choices(string.digits, k=10))
    return base + verhoeff.calc_check_digit(base)


def not_aadhaar():
    while True:
        s = "".join(random.choices(string.digits, k=12))
        if not verhoeff.is_valid(s):
            return s


def pan():
    while True:
        c = (
            "".join(random.choices(string.ascii_uppercase, k=3))
            + random.choice("PCHFATBLJG")
            + random.choice(string.ascii_uppercase)
            + "".join(random.choices(string.digits, k=4))
            + random.choice(string.ascii_uppercase)
        )
        if stdpan.is_valid(c):
            return c


def ssn():
    return f"{random.randint(100, 899)}-{random.randint(10, 99)}-{random.randint(1000, 9999)}"


def phone():
    return random.choice("6789") + "".join(random.choices(string.digits, k=9))


def card():
    n = fake.credit_card_number()
    return "-".join(n[i : i + 4] for i in range(0, 16, 4)) if len(n) == 16 else n


MESSAGES = [
    "Customer called from {phone} asking why the card was blocked.",
    "Please send statements to {email} from next month.",
    "KYC done at branch, Aadhaar {aadhaar} verified by officer.",
    "Refund of the reversed fee should go to UPI {upi} today.",
    "Customer wants a statement for account {acct} for the last quarter.",
    "Card blocked after a suspicious transaction, customer informed.",
    "Customer asked about the annual fee and was told it is waived.",
    "Address change request received, documents pending.",
    "Escalated to the branch manager for a callback tomorrow.",
]


def message(r):
    t = r.choice(MESSAGES)
    return t.format(
        phone=phone(),
        email=fake.email(),
        aadhaar=aadhaar(),
        acct=str(r.randint(10**10, 10**12)),
        upi=fake.user_name() + "@okaxis",
    )


def make_db(backend, n=300, seed=7):
    random.seed(seed)
    Faker.seed(seed)
    fake.seed_instance(seed)
    fake_gb.seed_instance(seed)
    fake.unique.clear()
    backend.admin_script(DDL)
    users, accounts, tickets = [], [], []
    for i in range(1, n + 1):
        users.append((i, fake.name(), fake.unique.email(), phone(), aadhaar(), pan(), ssn(), fake.city()))
        accounts.append(
            (i, i, card(), fake_gb.iban(), round(random.uniform(0, 900000), 2), random.choice(["active", "frozen"]))
        )
        tickets.append(
            (
                i,
                random.randint(1, n),
                phone(),
                card(),
                not_aadhaar(),
                random.choice(["Card blocked", "Statement request", "KYC update", "Fee reversal"]),
                random.choice(["open", "closed"]),
                message(random),
            )
        )
    backend.insert_many("users", users)
    backend.insert_many("accounts", accounts)
    backend.insert_many("support_tickets", tickets)
