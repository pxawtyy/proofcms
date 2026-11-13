# GeneXus detector fixture

This is **not** a vulnerable GeneXus application. It is a tiny static page
with the markers the GeneXus detector looks for (`gxajax`, `GXState`,
`gxcfg.js` and `gx.version`). It exists only to exercise the detector and
the `--cms genexus` path.

There is no high-severity CVE for GeneXus X Evolution 3 itself in NVD/CVE.
The only NVD-listed GeneXus CVE is CVE-2024-58288, a Windows service
unquoted-path local privilege escalation in GeneXus Protection Server
9.7.2.10, which cannot be reproduced in a Linux web lab.

## Bring-up

```bash
docker compose -f labs/genexus-fixture/compose.yml up -d --wait
python -m proofcms -u http://127.0.0.1:9218 --cms genexus --cve CVE-2024-58288
# detector: gxajax + GXState + gxcfg.js, version 3.0.0
# CVE-2024-58288: not the Protection Server 9.7.2.10 build -> INCONCLUSIVE
```

## Teardown

```bash
docker compose -f labs/genexus-fixture/compose.yml down -v
```
