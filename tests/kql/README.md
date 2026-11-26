# KQL tests

`run_tests.py` runs hunts and analytics against sample rows, so a query is tested for what it returns and not only for its syntax and column names.

It needs the Kusto emulator, a container image from Microsoft. Starting it accepts Microsoft's license terms for the emulator (`ACCEPT_EULA=Y`).

```bash
docker run -d --name kusto -e ACCEPT_EULA=Y -p 8080:8080 mcr.microsoft.com/azuredataexplorer/kustainer-linux:latest
python3 tests/kql/run_tests.py
```

Without an emulator the test is skipped. `--require` makes that a failure, and `--wait 120` waits for the emulator to start. Set `KUSTO_EMULATOR_URL` if it is not at `http://localhost:8080`.

## Adding cases for a query

Create `fixtures/<behaviors, general or framework>/<hunting or analytics>/<query file name>.jsonl`. For `general/sentinel/hunting/05-servers-resolving-out-of-band-testing-domains.kql` that is `fixtures/general/hunting/05-servers-resolving-out-of-band-testing-domains.jsonl`. One JSON object per line:

```json
{"name": "what this case shows", "expected": true, "rows": {"DnsEvents": [{"Computer": "{case}", "Name": "abc123.oast.fun"}]}}
```

- `rows` holds the rows of each table for this case. Tables and columns are the ones in `tools/kqlcheck/schema.json`. Columns you leave out are empty.
- `{case}` becomes an id that is unique to the case. The case counts as returned when that id appears anywhere in the results. Put it in the columns the query groups or joins by, usually the device name, so one case cannot affect another.
- `_ago` on a row is how long ago it happened, as a KQL timespan: `"10m"` (the default), `"3h"`, `"20d"`. It fills `Timestamp` and `TimeGenerated`.
- `expected` is `true` when the query must return the case and `false` when it must not.
- Every file needs at least one case that is returned and one near miss. Near misses are the valuable part.
- Rows are synthetic. No customer data, real user names, internal host names or internal addresses.

## How it works

Every table the query names is replaced by a `datatable` of the sample rows with the real column names and types, and the query runs as written after it. All the cases of a file run in one query. A query that fails to run fails the test, with Kusto's message.

The emulator is the Kusto engine, not Microsoft Sentinel or Defender. It shows that a query runs and what it returns for given rows. It does not show what a product writes into a column: build rows from events you have seen.
