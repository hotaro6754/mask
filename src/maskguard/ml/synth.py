"""Synthetic labelled columns for training the PII column classifier.

Everything here is generated from formats in public specifications (UIDAI Verhoeff, CBDT PAN structure, GSTN
mod-36 check, ECI EPIC, RBI IFSC, NPCI UPI handles, MoRTH vehicle plates). No real records are used, and no
benchmark code or data is used for training.

Each column gets 20-60 values, some nulls, some corrupted values, and a header drawn from one of three
conditions (truthful, generic or unrelated) so the model learns to trust values over names.
"""
import random, string
from datetime import date, datetime, timedelta

from faker import Faker
from stdnum import luhn, verhoeff

KINDS = ["aadhaar", "pan", "gstin", "upi", "phone", "pincode", "passport", "voter_id", "ifsc", "vehicle_reg",
         "bank_account", "name", "address", "email", "dob", "card", "iban", "ssn", "amount", "free_text", "none"]

_FAKERS = {}
B36 = string.digits + string.ascii_uppercase
STATES_VEH = ["MH", "DL", "KA", "TN", "UP", "GJ", "RJ", "WB", "AP", "TS", "KL", "PB", "HR", "MP", "BR", "OD", "AS", "JK"]
UPI_HANDLES = ["okaxis", "okhdfcbank", "oksbi", "okicici", "ybl", "ibl", "axl", "paytm", "apl", "upi", "kotak", "barodampay"]
BANKS = ["SBIN", "HDFC", "ICIC", "UTIB", "KKBK", "PUNB", "BARB", "CNRB", "IDIB", "YESB", "INDB", "UBIN"]
HINDI_MONTHS = ["जनवरी", "फ़रवरी", "मार्च", "अप्रैल", "मई", "जून", "जुलाई", "अगस्त", "सितंबर", "अक्टूबर", "नवंबर", "दिसंबर"]
EN_MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def fk(locale):
    if locale not in _FAKERS:
        _FAKERS[locale] = Faker(locale)
    return _FAKERS[locale]


def _digits(r, n):
    return "".join(r.choices(string.digits, k=n))


def _letters(r, n):
    return "".join(r.choices(string.ascii_uppercase, k=n))


# ---- positive generators --------------------------------------------------------------------------------------
def aadhaar(r, u=None):
    base = str(r.randint(2, 9)) + _digits(r, 10)
    v = base + verhoeff.calc_check_digit(base)
    style = r.random() if u is None else u
    if style < 0.15:
        return f"XXXX XXXX {v[-4:]}"
    if style < 0.5:
        return f"{v[:4]} {v[4:8]} {v[8:]}"
    if style < 0.6:
        return f"{v[:4]}-{v[4:8]}-{v[8:]}"
    return v


def pan(r, fourth=None):
    return _letters(r, 3) + (fourth or r.choice("PCHFATBLJG")) + _letters(r, 1) + _digits(r, 4) + _letters(r, 1)


def gstin(r):
    body = f"{r.randint(1, 37):02d}" + pan(r) + r.choice("123456789ABCDEFGHJKLMNPQRSTUVWXYZ") + "Z"
    return body + luhn.calc_check_digit(body, alphabet=B36)


def upi(r, u=None):
    style = r.random() if u is None else u
    if style < 0.35:
        local = fk("en_IN").first_name().lower() + r.choice([".", "", "_"]) + fk("en_IN").last_name().lower()
    elif style < 0.6:
        local = r.choice("6789") + _digits(r, 9)
    else:
        local = fk("en_IN").user_name() + str(r.randint(1, 99))
    return f"{local}@{r.choice(UPI_HANDLES)}"


def phone(r, u=None):
    n = r.choice("6789") + _digits(r, 9)
    style = r.random() if u is None else u
    if style < 0.35:
        return n
    if style < 0.55:
        return f"+91 {n[:5]} {n[5:]}"
    if style < 0.7:
        return f"+91-{n}"
    if style < 0.8:
        return f"0{n}"
    if style < 0.9:
        return f"{n[:5]} {n[5:]}"
    return f"+91{n}"


def pincode(r):
    return str(r.randint(1, 8)) + _digits(r, 5)


def passport(r):
    return r.choice("ABCDEFGHJKLMNPRSTUVWXYZ") + str(r.randint(1, 9)) + _digits(r, 6)


def voter_id(r):
    d = _digits(r, 6)
    return _letters(r, 3) + d + luhn.calc_check_digit(d)


def ifsc(r):
    return r.choice(BANKS) + "0" + "".join(r.choices(string.digits + string.ascii_uppercase, k=6))


def vehicle_reg(r, u=None):
    if r.random() < 0.1:
        return f"{r.randint(21, 26)} BH {_digits(r, 4)} {_letters(r, 2)}"
    st, dist, ser, num = r.choice(STATES_VEH), f"{r.randint(1, 99):02d}", _letters(r, r.choice([1, 2])), _digits(r, 4)
    sep = r.choice([" ", "", "-"]) if u is None else [" ", "", "-"][int(u * 3) % 3]
    return sep.join([st, dist, ser, num])


def bank_account(r):
    return str(r.randint(1, 9)) + _digits(r, r.randint(8, 17))


def name(r, u=None):
    if u is None:
        loc = r.choice(["en_IN", "en_IN", "en_IN", "hi_IN"])
    else:
        loc = "hi_IN" if u < 0.25 else "en_IN"
    n = fk(loc).name()
    if loc == "en_IN" and (r.random() if u is None else (u * 7) % 1) < 0.15:
        n = n.upper()
    return n


def address(r, u=None):
    loc = r.choice(["en_IN", "en_IN", "hi_IN"]) if u is None else ("hi_IN" if u < 0.3 else "en_IN")
    return fk(loc).address().replace("\n", ", ")


def email(r):
    return fk(r.choice(["en_IN", "en_US"])).email()


def _birth(r):
    return date(1940, 1, 1) + timedelta(days=r.randint(0, 365 * 66))


def _fmt_date(r, d, hindi_ok=True, u=None):
    style = r.random() if u is None else u
    if style < 0.3:
        return d.strftime("%d/%m/%Y")
    if style < 0.5:
        return d.strftime("%d-%m-%Y")
    if style < 0.75:
        return d.isoformat()
    if style < 0.9 or not hindi_ok:
        return f"{d.day:02d} {EN_MONTHS[d.month - 1]} {d.year}"
    return f"{d.day:02d} {HINDI_MONTHS[d.month - 1]} {d.year}"


def dob(r, u=None):
    return _fmt_date(r, _birth(r), u=u)


def card(r, u=None):
    n = fk("en_US").credit_card_number(card_type=r.choice(["visa16", "mastercard", "amex", "discover", "jcb16", None]))
    style = r.random() if u is None else u
    if len(n) == 16 and style < 0.35:
        return "-".join(n[i:i + 4] for i in range(0, 16, 4))
    if len(n) == 16 and style < 0.6:
        return " ".join(n[i:i + 4] for i in range(0, 16, 4))
    return n


def iban(r):
    return fk(r.choice(["en_GB", "de_DE", "fr_FR", "nl_NL", "es_ES"])).iban()


def ssn(r):
    return f"{r.randint(100, 899)}-{r.randint(10, 99)}-{r.randint(1000, 9999)}"


def _indian_grouping(n):
    s = str(n)
    if len(s) <= 3:
        return s
    head, tail = s[:-3], s[-3:]
    parts = []
    while len(head) > 2:
        parts.insert(0, head[-2:])
        head = head[:-2]
    return ",".join([head] + parts + [tail]) if head else ",".join(parts + [tail])


def amount(r, u=None, band=None):
    lo, width = band if band else (r.uniform(0, 5), r.uniform(1, 3))  # log10 range: columns sit in a band
    v = round(10 ** r.uniform(lo, lo + width), 2)
    style = r.random() if u is None else u
    if style < 0.2:
        return f"{v:.2f}"
    if style < 0.35:
        return f"₹{v:,.2f}"
    if style < 0.5:
        return f"₹{int(v):,}"
    if style < 0.6:
        return f"₹{_indian_grouping(int(v))}"
    if style < 0.7:
        return f"Rs. {_indian_grouping(int(v))}"
    if style < 0.8:
        return f"INR {int(v):,}"
    if style < 0.9:
        return f"{v:,.2f}"
    return str(int(v))


def free_text(r):
    f = fk("en_IN")
    s = f.sentence(nb_words=r.randint(6, 16))
    if r.random() < 0.35:  # some notes carry PII inside the text
        s += " " + r.choice([f"Call {phone(r)}.", f"Email {email(r)}.", f"Aadhaar {aadhaar(r)}.", f"PAN {pan(r)}.",
                             f"UPI {upi(r)}."])
    return s


# ---- negatives: things that look like identifiers but are not personal data --------------------------------
def _neg(r):
    kind = r.choice(["order12", "utr", "otp", "pan_sku", "invoice", "ipv4", "timestamp", "gstin_bad", "uuid",
                     "product", "city", "status", "seq", "note", "hexhash", "date_recent", "qty", "percent",
                     "url", "year", "sku", "txn", "category", "category", "plan", "dept", "city_set"])
    return kind


CATEGORY_POOL = ["Card Blocked", "Statement Request", "KYC Update", "Fee Reversal", "Address Change", "Loan Enquiry",
                 "Cheque Book", "Net Banking", "Account Closure", "Fixed Deposit", "Mobile Banking", "Credit Limit",
                 "Debit Card", "Home Loan", "Car Loan", "Personal Loan", "Savings Account", "Current Account",
                 "Gold Plus", "Platinum Rewards", "Silver Saver", "Basic Plan", "Premium Plan", "Customer Service",
                 "Human Resources", "Risk Management", "Retail Banking", "Wealth Management", "Branch Operations",
                 "High Priority", "Low Priority", "Pending Review", "Under Investigation", "Resolved Closed"]
_COLUMN_CHOICES = {}


def _column_choice(r, key, pool, k):
    """Low-cardinality categorical columns: a fixed handful of labels per column, repeated."""
    if key not in _COLUMN_CHOICES:
        _COLUMN_CHOICES[key] = r.sample(pool, k)
    return r.choice(_COLUMN_CHOICES[key])


def negative(r, kind, col_key=None):
    if kind in ("category", "plan", "dept"):
        return _column_choice(r, (col_key, kind), CATEGORY_POOL, r.randint(3, 8))
    if kind == "city_set":
        return _column_choice(r, (col_key, kind), [fk("en_IN").city() for _ in range(30)], r.randint(3, 10))
    if kind == "order12":
        while True:
            s = str(r.randint(1, 9)) + _digits(r, 11)
            if not verhoeff.is_valid(s):
                return s
    if kind == "utr":
        return r.choice(BANKS) + r.choice("RNH") + _digits(r, 4) + _digits(r, 13)
    if kind == "otp":
        return _digits(r, 6)
    if kind == "pan_sku":
        return pan(r, fourth=r.choice("DEIKMNOQRSUVWXYZ"))
    if kind == "invoice":
        return f"{r.choice(['INV', 'BILL', 'PO', 'SO'])}-{r.randint(2019, 2026)}-{r.randint(1, 999999):06d}"
    if kind == "ipv4":
        return ".".join(str(r.randint(1, 254)) for _ in range(4))
    if kind == "timestamp":
        d = datetime(2000, 1, 1) + timedelta(seconds=r.randint(0, 26 * 365 * 86400))
        return d.isoformat(sep=r.choice([" ", "T"]))
    if kind == "gstin_bad":
        g = gstin(r)
        return g[:-1] + r.choice([c for c in B36 if c != g[-1]])
    if kind == "uuid":
        return fk("en_US").uuid4()
    if kind == "product":
        return fk("en_US").catch_phrase()
    if kind == "city":
        return fk("en_IN").city()
    if kind == "status":
        return r.choice(["active", "inactive", "pending", "closed", "frozen", "open", "SUCCESS", "FAILED"])
    if kind == "seq":
        return str(r.randint(1, 100000))
    if kind == "note":
        return f"note-{r.randint(0, 999999)}"
    if kind == "hexhash":
        return "%032x" % r.getrandbits(128)
    if kind == "date_recent":
        return _fmt_date(r, date(2000, 1, 1) + timedelta(days=r.randint(0, 26 * 365)), hindi_ok=False)
    if kind == "qty":
        return str(r.randint(0, 500))
    if kind == "percent":
        return f"{r.uniform(0, 100):.1f}%"
    if kind == "url":
        return fk("en_US").url()
    if kind == "year":
        return str(r.randint(1990, 2026))
    if kind == "sku":
        return f"{_letters(r, 3)}-{_digits(r, 4)}-{r.choice(['S', 'M', 'L', 'XL'])}"
    if kind == "txn":
        return "TXN" + _digits(r, r.randint(8, 14))
    raise ValueError(kind)


GENERATORS = {"aadhaar": aadhaar, "pan": pan, "gstin": gstin, "upi": upi, "phone": phone, "pincode": pincode,
              "passport": passport, "voter_id": voter_id, "ifsc": ifsc, "vehicle_reg": vehicle_reg,
              "bank_account": bank_account, "name": name, "address": address, "email": email, "dob": dob,
              "card": card, "iban": iban, "ssn": ssn, "amount": amount, "free_text": free_text}

STYLED = {"aadhaar", "upi", "phone", "card", "amount", "name", "dob", "vehicle_reg", "address"}

TRUTHFUL = {
    "aadhaar": ["aadhaar", "aadhaar_no", "aadhar_number", "uid", "uidai_no"], "pan": ["pan", "pan_no", "pan_card"],
    "gstin": ["gstin", "gst_no", "gst_number"], "upi": ["upi_id", "vpa", "upi_handle"],
    "phone": ["phone", "mobile", "mobile_no", "contact_number", "msisdn"], "pincode": ["pincode", "pin_code", "zip"],
    "passport": ["passport_no", "passport"], "voter_id": ["voter_id", "epic_no"], "ifsc": ["ifsc", "ifsc_code"],
    "vehicle_reg": ["vehicle_no", "registration_no", "reg_number"], "bank_account": ["account_no", "acct_number", "bank_ac"],
    "name": ["name", "full_name", "customer_name", "holder_name"], "address": ["address", "addr", "residential_address"],
    "email": ["email", "email_id", "mail"], "dob": ["dob", "date_of_birth", "birth_date"],
    "card": ["card_number", "cc_no", "credit_card"], "iban": ["iban"], "ssn": ["ssn", "social_security_no"],
    "amount": ["balance", "amount", "salary", "outstanding"], "free_text": ["notes", "remarks", "comment", "description"],
    "none": ["status", "created_at", "sku", "city", "order_id", "txn_ref", "ip_address", "qty"],
}
GENERIC = ["col_1", "col_07", "field_a", "field_x", "c12", "attr_3", "x", "value", "data", "f9", "column3"]
UNRELATED = ["ref", "code", "external_id", "meta", "tag", "ref_no", "key", "label", "entry", "token", "item",
             "record_ref", "source", "info", "remark_code", "batch", "slot", "lookup"]


def _corrupt(r, v):
    if not v:
        return v
    op = r.random()
    if op < 0.3:
        return v + r.choice("!#?*")
    if op < 0.6:
        return v[: max(1, len(v) - r.randint(1, 3))]
    i = r.randrange(len(v))
    return v[:i] + r.choice(string.ascii_letters + string.digits) + v[i + 1:]


def make_column(r, kind):
    n = r.randint(20, 60)
    if kind == "none":
        sub = _neg(r)
        key = r.random()
        values = [negative(r, sub, key) for _ in range(n)]
    else:
        gen = GENERATORS[kind]
        if kind == "amount":
            band = (r.uniform(0, 5), r.uniform(0.5, 3))
            u = r.random() if r.random() < 0.6 else None
            values = [amount(r, u, band) for _ in range(n)]
        elif kind in STYLED and r.random() < 0.6:  # most real columns use one format throughout
            u = r.random()
            values = [gen(r, u) for _ in range(n)]
        else:
            values = [gen(r) for _ in range(n)]
    null_p, bad_p = r.choice([0, 0.05, 0.1]), r.choice([0, 0.05, 0.1])
    values = [None if r.random() < null_p else (_corrupt(r, v) if r.random() < bad_p else v) for v in values]
    cond = r.random()
    if cond < 0.4:
        header = r.choice(TRUTHFUL[kind])
    elif cond < 0.7:
        header = r.choice(GENERIC)
    else:
        header = r.choice(UNRELATED)
    return header, values


def dataset(n_per_kind, seed):
    r = random.Random(seed)
    for loc in ("en_IN", "hi_IN", "en_US", "en_GB", "de_DE", "fr_FR", "nl_NL", "es_ES"):
        fk(loc).seed_instance(seed)
    out = []
    for kind in KINDS:
        reps = n_per_kind * (3 if kind == "none" else 1)
        for _ in range(reps):
            header, values = make_column(r, kind)
            out.append((header, values, kind))
    r.shuffle(out)
    return out
