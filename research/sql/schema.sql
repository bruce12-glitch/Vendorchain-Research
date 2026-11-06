CREATE TABLE IF NOT EXISTS submissions(
  id TEXT PRIMARY KEY, vendor_id TEXT NOT NULL, document_hash TEXT NOT NULL,
  cipher_hash TEXT NOT NULL, envelope TEXT NOT NULL, context TEXT NOT NULL,
  blob_path TEXT NOT NULL, state TEXT NOT NULL, version INTEGER NOT NULL,
  lease_until DOUBLE PRECISION NOT NULL DEFAULT 0, created DOUBLE PRECISION NOT NULL);
CREATE TABLE IF NOT EXISTS outbox(
  id TEXT PRIMARY KEY REFERENCES submissions(id), payload TEXT NOT NULL,
  snapshot INTEGER NOT NULL, status TEXT NOT NULL, tx_id TEXT);
CREATE TABLE IF NOT EXISTS digest_replays(
  digest TEXT PRIMARY KEY, record_id TEXT NOT NULL, received DOUBLE PRECISION NOT NULL);
CREATE INDEX IF NOT EXISTS digest_replays_expiry ON digest_replays(received);
CREATE TABLE IF NOT EXISTS events(
  seq BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, record_id TEXT NOT NULL,
  event TEXT NOT NULL, prev_hash TEXT NOT NULL, event_hash TEXT NOT NULL);
CREATE OR REPLACE FUNCTION vendorchain_immutable() RETURNS trigger AS $$
BEGIN RAISE EXCEPTION 'immutable VendorChain evidence'; END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS immutable_events ON events;
CREATE TRIGGER immutable_events BEFORE UPDATE OR DELETE ON events
  FOR EACH ROW EXECUTE FUNCTION vendorchain_immutable();
DROP TRIGGER IF EXISTS immutable_submission ON submissions;
CREATE TRIGGER immutable_submission BEFORE UPDATE OF vendor_id,document_hash,cipher_hash,envelope,context,blob_path ON submissions
  FOR EACH ROW EXECUTE FUNCTION vendorchain_immutable();
DROP TRIGGER IF EXISTS immutable_payload ON outbox;
CREATE TRIGGER immutable_payload BEFORE UPDATE OF payload ON outbox
  FOR EACH ROW EXECUTE FUNCTION vendorchain_immutable();
