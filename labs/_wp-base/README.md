# Fast WordPress fixture

One pinned WordPress 6.4.3 + MariaDB 10.11 stack on `127.0.0.1:9212`, with a
WP-CLI service. Use it for WordPress CVE validation instead of creating and
building a new compose file per plugin.

```bash
python tools/wp_lab.py up
python tools/wp_lab.py install https://downloads.wordpress.org/plugin/woocommerce.8.6.1.zip
python tools/wp_lab.py install https://downloads.wordpress.org/plugin/woocommerce-payments.5.6.1.zip
python -m proofcms -u http://127.0.0.1:9212 --cve CVE-2023-28121 --run-exploit CVE-2023-28121 --exploit-mode safe --i-understand-authorized --i-understand-lab-only
python tools/wp_lab.py reset
python tools/wp_lab.py down
```

`install` accepts a WordPress.org URL or a local zip; local zips are mounted
read-only at `/fixtures` for the WP-CLI container. `reset` deactivates and
deletes plugins, drops the database, and reinstalls WordPress in place, so the
base container does not need a rebuild.

The stack is loopback-only; `down` uses `down -v` to remove the database and
WordPress volumes. Plugin archives are never committed.
