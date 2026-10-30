-- PostgreSQL Anonymizer 3.2.3 configuration mirroring MaskGuard's "support" role on the same fixture.
-- Masking functions follow docs/masking_functions.md; the row restriction uses PostgreSQL RLS, which is what the
-- Anonymizer docs recommend for row-level control (docs/dynamic_masking.md, "Principles").
ALTER DATABASE rea SET anon.transparent_dynamic_masking TO true;
SECURITY LABEL FOR anon ON COLUMN customers.email IS 'MASKED WITH FUNCTION anon.partial_email(email)';
SECURITY LABEL FOR anon ON COLUMN customers.ssn   IS 'MASKED WITH FUNCTION anon.partial(ssn,0,$$XXX-XX-$$,4)';
SECURITY LABEL FOR anon ON COLUMN customers.phone IS 'MASKED WITH FUNCTION anon.partial(phone,0,$$XXX-$$,4)';
SECURITY LABEL FOR anon ON COLUMN accounts.card   IS 'MASKED WITH FUNCTION anon.partial(card,4,$$-XXXX-XXXX-$$,4)';
-- Custom mask in a dedicated TRUSTED schema, the documented pattern (docs/UPGRADE.md, runbooks/3-anonymous_dumps.md):
-- the target rejects pg_catalog.trunc() directly because pg_catalog is not a trusted schema.
CREATE SCHEMA my_masks;
SECURITY LABEL FOR anon ON SCHEMA my_masks IS 'TRUSTED';
CREATE FUNCTION my_masks.bucket(v numeric) RETURNS numeric LANGUAGE sql IMMUTABLE AS $$ SELECT trunc(v, -4) $$;
GRANT USAGE ON SCHEMA my_masks TO PUBLIC;
SECURITY LABEL FOR anon ON COLUMN accounts.balance IS 'MASKED WITH FUNCTION my_masks.bucket(balance)';
DROP ROLE IF EXISTS support_m; CREATE ROLE support_m LOGIN PASSWORD 'rea-local-only';
SECURITY LABEL FOR anon ON ROLE support_m IS 'MASKED';
GRANT USAGE ON SCHEMA public TO support_m;
GRANT SELECT ON customers, accounts TO support_m;
ALTER TABLE accounts ENABLE ROW LEVEL SECURITY;
CREATE POLICY support_not_frozen ON accounts FOR SELECT TO support_m USING (status <> 'frozen');
CREATE POLICY owner_all ON accounts TO postgres USING (true);
