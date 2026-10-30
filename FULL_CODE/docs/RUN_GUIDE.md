# Run MaskGuard: command line, Control Room and Streamlit, on your database, with logins

Every step below was run end to end on the organisers' Saffron Bank pack (SQLite, and MySQL with the pack's
non-admin `saffron` user) on 30 October 2026.

There are three ways in, and they all use the same engine and the same logins:

| | Start it with | Open | Best for |
|---|---|---|---|
| **Command line** | `maskguard …` | the terminal | IT teams, scripts, the live demo |
| **Control Room** (HTML dashboard) | `maskguard serve` | http://127.0.0.1:8000/ui/ | the demo for judges: playground, PII discovery, audit |
| **Streamlit dashboard** (classic) | `maskguard dashboard --classic --port 8501` | http://127.0.0.1:8501 | quick query console, attack suite, threat monitor |

## Logins: how they work

Every query runs as a person with a role (admin, support, analyst, auditor). The role decides what is masked.

- **On the built-in demo bank**, demo logins are on: one click per role in the Control Room ("Switch identity"), a
  role toggle in Streamlit. Demo users: `admin.ann / admin123`, `support.sam / support123`,
  `analyst.ali / analyst123`, `auditor.aud / auditor123`.
- **On your own database**, you create real logins from a CSV (step 3). Each person signs in with a username and
  password. The role comes from the users file on the server, never from the browser.
- **Passwords** are stored only as PBKDF2 hashes in `users.yaml`. The plain passwords are written once to
  `passwords.yaml`, which only you can read. Hand them out, then delete that file.

## 0. Install, once

From a checkout of this repository:

```bash
python3 -m venv ~/mg-venv && source ~/mg-venv/bin/activate
pip install -e /path/to/mask          # the `maskguard` command now works in any folder
maskguard --version
```

(Or, inside the repository, prefix every command with `uv run`.)

## 1. Make a folder for this database

MaskGuard keeps its settings, logins, review decisions and audit log in the folder you run it from.

```bash
mkdir ~/saffron-demo && cd ~/saffron-demo
cp /path/to/B1_Smart_Data_Masking_PII/data/users.csv .
```

## 2. Connect the database

Pick one. `connect` tests the connection, installs MaskGuard's masking functions in the database, scans every
column for personal data, and saves the settings in `./maskguard.yaml`. It never changes your data.

**SQLite** (the pack's file):

```bash
cp /path/to/B1_Smart_Data_Masking_PII/sql/sqlite/saffron_bank.db .
maskguard connect "sqlite:///$PWD/saffron_bank.db"
```

**PostgreSQL** (the pack's `docker compose up -d`: port 55432, user `saffron`):

```bash
maskguard connect "postgresql://saffron:saffron_local_only@127.0.0.1:55432/saffron_bank"
```

**MySQL** (the pack's docker compose: port 53306). The pack's `saffron` user may not create functions while MySQL's
binary log is on (error 1419), so install them once with the root account, then connect as `saffron`:

```bash
MASKGUARD_DB_ADMIN="mysql://root:root_local_only@127.0.0.1:53306/saffron_bank" maskguard db-install
maskguard connect "mysql://saffron:saffron_local_only@127.0.0.1:53306/saffron_bank"
```

You should see: `connected … 9 tables · 120 columns`, then how many sensitive columns were found and how many are
`UNREVIEWED` (masked for everyone but admin until someone reviews them).

## 3. Create the logins from a CSV

```bash
maskguard users import users.csv --use
```

The CSV needs a `username` and a `role` column (`display_name` is optional). Roles must be admin, support, analyst
or auditor, in any case. This writes:
- `users.yaml`: hashes only;
- `passwords.yaml`: the generated passwords (only you can read it).

`--use` makes this folder use them and turns demo logins off. To read a password:

```bash
grep support_ravi passwords.yaml
```

## 4. Review: decide which columns are not personal

Until a column is reviewed it stays masked for everyone but admin, including ids and keys. A query that joins on a
masked key (`customer_id`) finds nothing useful and can time out, so do this step before the demo.

- **For the Saffron pack:** use the review we wrote from the answer key. It marks the 71 non-personal columns
  (ids, keys, dates, codes, statuses, the bank's own branch data) as public:

  ```bash
  mkdir -p policies && cp /path/to/mask/bench/saffron/reviewed_overrides.yaml policies/overrides.yaml
  ```

- **For any other database:**

  ```bash
  maskguard pii list                              # what was found and why (never values)
  maskguard pii approve --suggested               # ids and status lists the scanner suggests; check the list it prints
  maskguard pii approve customers.customer_id …   # the rest you decide are not personal
  maskguard pii tag customers.city --tag PII_MEDIUM
  ```

## 5. Use it

### Command line

```bash
maskguard query --user support_ravi "SELECT cust_nm, mob_no, pan_no, curr_bal FROM customers JOIN kyc_records USING (customer_id) JOIN accounts USING (customer_id) ORDER BY customer_id LIMIT 3"
```

It asks for the password; or add `--password '…'`. Run the same query as `admin_anita` and `analyst_kavya` to see
the three views. More: `maskguard query --user support_ravi "UPDATE accounts SET curr_bal = 0"` (refused),
`maskguard integrity proof`, `maskguard audit verify`.

### Control Room (HTML)

```bash
maskguard serve                 # keep this terminal open
```

1. Open **http://127.0.0.1:8000/ui/**.
2. Click **Sign in** (top right), enter `support_ravi` and the password from `passwords.yaml`.
3. Open **Masking playground** → **SQL editor**, paste the query above, press **Run**. Scroll down to **Why each field
   looks the way it does**.
4. **Sign out**, sign in as `analyst_kavya`, and run it again.
5. As `admin_anita`: **PII discovery** (type `pan` in the search box: `col_7` is found as PAN), **Audit explorer**,
   **Data integrity**.

The API documentation is at http://127.0.0.1:8000/docs; Postman uses the same logins.

### Streamlit dashboard

```bash
maskguard dashboard --classic --port 8501
```

1. Open **http://127.0.0.1:8501**.
2. In the left sidebar, open **Log in with a username and password**, enter `support_ravi` and the password.
3. **Query console**: pick an example (one per table) or type SQL, press **Run query**.

On the demo bank, Streamlit can also show all roles side by side. On your own database it runs as the person signed
in.

## Back to the demo bank

```bash
maskguard connect --demo        # the bundled synthetic bank, with one-click demo logins
```

## When something goes wrong

| You see | Do this |
|---|---|
| `MASKGUARD_DB is set in your environment and wins` | `unset MASKGUARD_DB`, then `connect` again |
| MySQL `1419 … SUPER privilege and binary logging` | run `maskguard db-install` once with the root account (step 2) |
| `masking functions are missing or not executable` | the same: `maskguard db-install` with an owner account |
| A join returns `time limit exceeded` or odd results | the join key is still `UNREVIEWED`: step 4 |
| `Bad credentials` | check the username and the password in `passwords.yaml`; recreate with `maskguard users import users.csv --use --force` |
| `address already in use` | another copy is running: use `--port 8010` (Control Room) or `--port 8502` (Streamlit) |
| Control Room shows "Demo identities are off" | expected on your own database: sign in with a username and password |

For a production setup (HTTPS, read-only database account, a separate user file), see
[DEPLOYMENT.md](DEPLOYMENT.md).
