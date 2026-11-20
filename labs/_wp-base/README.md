# Fast WordPress fixture

One pinned WordPress 6.4.3 + MariaDB 10.11 stack on `127.0.0.1:9212`, with a
long-running WP-CLI container. Use it for WordPress CVE validation instead
of creating and building a new compose file per plugin.

```bash
python tools/wp_lab.py up
python tools/wp_lab.py install https://downloads.wordpress.org/plugin/woocommerce.8.6.1.zip
python tools/wp_lab.py install https://downloads.wordpress.org/plugin/woocommerce-payments.5.6.1.zip
python -m proofcms -u http://127.0.0.1:9212 --cve CVE-2023-28121 --run-exploit CVE-2023-28121 --exploit-mode safe --i-understand-authorized --i-understand-lab-only
python tools/wp_lab.py reset
python tools/wp_lab.py down
```

`install` accepts a WordPress.org URL or a local zip, downloads URLs once to
the fixture cache, copies the archive into the CLI container, and activates
the plugin. `up` installs WordPress once and writes a database + plugin
snapshot; `reset` restores that snapshot in place, so the base container is
never rebuilt. MariaDB runs on tmpfs (snapshot restores take seconds); the
snapshot on the host is the persistence layer.

One-shot vulnerable/patched validation returns compact JSON:

```bash
python tools/wp_lab.py validate --cve CVE-2024-10402 \
  --vuln https://downloads.wordpress.org/plugin/forminator.1.35.1.zip \
  --patched https://downloads.wordpress.org/plugin/forminator.1.36.0.zip \
  --mode aggressive
```

The declarative form lives in `labs/<cve>/lab.json`:

```bash
python tools/wp_lab.py run labs/cve-2024-10402 --pretty
```

The stack is loopback-only; `down` uses `down -v` to remove the database and
WordPress volumes and deletes the now-stale host snapshot. Pass
`--keep-snapshot` only if the containers stay up. Plugin archives are never
committed.
