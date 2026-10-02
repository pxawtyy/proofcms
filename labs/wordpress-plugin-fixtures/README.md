# WordPress vulnerable plugin fixture lab

This loopback-only lab combines three user-supplied historical WordPress plugins. The fixture directories remain on the archive drive and are mounted read-only.

| CVE | Plugin | Fixture |
|---|---|---:|
| CVE-2020-35489 | Contact Form 7 | 5.3.1 |
| CVE-2023-3460 | Ultimate Member | 2.6.6 |
| CVE-2024-28000 | LiteSpeed Cache | 6.3.0.1 |

Start WordPress and perform the one-time installation:

```powershell
docker compose up -d --build
docker compose --profile tools run --rm cli core install --url=http://127.0.0.1:9210 --title=ProofCMS --admin_user=admin --admin_password=proofcms-lab-password --admin_email=lab@example.test --skip-email --allow-root
docker compose --profile tools run --rm cli plugin activate contact-form-7 litespeed-cache ultimate-member --allow-root
```

Run all three assessments:

```powershell
python -m proofcms -u http://127.0.0.1:9210 --cms wordpress --cve CVE-2020-35489,CVE-2023-3460,CVE-2024-28000
```

These modules currently perform passive component/version assessment. A complete active laboratory for each CVE additionally requires its affected configuration and a tightly scoped validation contract.

Remove the disposable database and site with `docker compose down -v`.
