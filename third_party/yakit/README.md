# Yakit fingerprint rules

Extracted on 2026-08-09 from the local Yakit plugin database
(`~/yakit-projects/yakit-profile-plugin.db`, `yak_scripts` row 2058
“被动指纹检测”) into `fingerprint.json`.

Format per rule:

```json
{
  "cms": "seeyon",
  "method": "keyword",
  "location": "body",
  "keyword": ["/seeyon/USER-DATA/IMAGES/LOGIN/login.gif"]
}
```

- `method=keyword` matches a substring in `location` (`body` or `header`).
- `method=faviconhash` matches the site favicon hash; the hash is the signed
  32-bit MurmurHash3 (`mmh3.hash(base64(favicon_content))`, Shodan-compatible)
  implemented in pure Python by `tools/http/fingerprint.py`.

650 rules total: 135 keyword + 515 faviconhash. The Yakit plugin library is
AGPL-3.0; the extracted rule data is kept as reference data for the AION
competition run.
