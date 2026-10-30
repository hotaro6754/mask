"""Synthetic clinic database for the end-to-end test: a different domain, schema and naming from MaskGuard's demo
bank, with misleading column names (contact = email, ref_code = card) and a decoy (invoice_no: 12 digits, not Aadhaar).

    python load_clinic.py postgresql://OWNER:PW@HOST:PORT/clinic
"""

import random
import sys

import psycopg
from faker import Faker

from maskguard.seed import aadhaar, card, not_aadhaar, pan, phone

random.seed(11)
fake = Faker("en_IN")
Faker.seed(11)
conn = psycopg.connect(sys.argv[1], autocommit=True)
conn.execute("""
CREATE TABLE patients (patient_no INTEGER PRIMARY KEY, full_name TEXT, dob DATE, mobile_no TEXT, contact TEXT,
                       aadhaar_no TEXT, pan_card TEXT, city TEXT, blood_group TEXT);
CREATE TABLE visits (visit_id INTEGER PRIMARY KEY, patient_no INTEGER, doctor TEXT, ward TEXT, visit_date DATE,
                     diagnosis_code TEXT, remarks TEXT, status TEXT);
CREATE TABLE billing (bill_id INTEGER PRIMARY KEY, patient_no INTEGER, ref_code TEXT, upi_handle TEXT,
                      amount NUMERIC(12,2), paid TEXT, invoice_no TEXT);
""")
N = 250
patients = [
    (
        i,
        fake.name(),
        fake.date_of_birth(minimum_age=1, maximum_age=90),
        phone(),
        fake.unique.email(),
        aadhaar(),
        pan(),
        fake.city(),
        random.choice(["A+", "B+", "O+", "AB+", "A-", "O-"]),
    )
    for i in range(1, N + 1)
]
REMARKS = [
    "Follow-up in two weeks; patient reports mild improvement.",
    "Relative called from {phone} to reschedule the next appointment.",
    "Insurance claim pending; patient asked for a printed copy of the report.",
    "Patient shared Aadhaar {aadhaar} at the desk for the government scheme form.",
    "Advised rest and fluids; no further tests needed at this stage.",
]
visits, bills = [], []
for v in range(1, 2 * N + 1):
    p = patients[random.randrange(N)]
    r = random.choice(REMARKS).format(phone=p[3], aadhaar=p[5])
    visits.append(
        (
            v,
            p[0],
            "Dr. " + fake.last_name(),
            random.choice(["OPD", "Cardiology", "Ortho", "Pediatrics"]),
            fake.date_between(start_date="-1y"),
            random.choice(["J45.909", "I10", "E11.9", "M54.5", "K21.9"]),
            r,
            random.choice(["completed", "scheduled", "cancelled"]),
        )
    )
for b in range(1, N + 1):
    p = patients[random.randrange(N)]
    first = p[1].split()[0].lower()
    bills.append(
        (
            b,
            p[0],
            card(),
            f"{first}{random.randint(1, 99)}@ok{random.choice(['axis', 'sbi', 'hdfcbank'])}",
            round(random.uniform(300, 85000), 2),
            random.choice(["yes", "no"]),
            not_aadhaar(),
        )
    )
with conn.cursor() as c:
    c.executemany("INSERT INTO patients VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)", patients)
    c.executemany("INSERT INTO visits VALUES (%s,%s,%s,%s,%s,%s,%s,%s)", visits)
    c.executemany("INSERT INTO billing VALUES (%s,%s,%s,%s,%s,%s,%s)", bills)
for t in ("patients", "visits", "billing"):
    print(t, conn.execute(f"SELECT count(*) FROM {t}").fetchone()[0], "rows")
