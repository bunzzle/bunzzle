CREATE TABLE dmarc_reports (
  id          INTEGER PRIMARY KEY,
  org         TEXT NOT NULL,
  report_id   TEXT NOT NULL,
  email       TEXT,
  domain      TEXT NOT NULL,
  policy      TEXT NOT NULL,
  begin_at    INTEGER NOT NULL,
  end_at      INTEGER NOT NULL,
  received_at INTEGER NOT NULL,
  UNIQUE (org, report_id)
) STRICT;

CREATE INDEX dmarc_reports_domain ON dmarc_reports (domain, begin_at);

CREATE TABLE dmarc_rows (
  report        INTEGER NOT NULL REFERENCES dmarc_reports (id) ON DELETE CASCADE,
  source_ip     TEXT NOT NULL,
  count         INTEGER NOT NULL,
  disposition   TEXT NOT NULL,
  dkim          TEXT NOT NULL,
  spf           TEXT NOT NULL,
  header_from   TEXT NOT NULL,
  envelope_from TEXT,
  dkim_domains  TEXT NOT NULL,
  spf_domain    TEXT
) STRICT;

CREATE INDEX dmarc_rows_report ON dmarc_rows (report);
