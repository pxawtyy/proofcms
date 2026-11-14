# ProofCMS lab acquisition matrix

This file lists the packages and runtime versions needed to reproduce every implemented ProofCMS module and the
researched modules currently waiting for fixtures. Keep vulnerable packages outside Git and record the original
filename, source URL, SHA-256, license, and acquisition date in a local inventory.

One representative vulnerable release per CVE is normally enough. When a CVE has materially different affected
branches, retain one package per branch boundary.

## Generic web libraries

| CVE | Package/script to retain | Vulnerable range | Recommended fixture | Extra requirements |
|---|---|---:|---:|---|
| CVE-2018-9206 | `blueimp/jQuery-File-Upload` | through 9.22.0 | tag `v9.22.0` | Apache/PHP sample handler at `server/php/index.php`; writable `server/php/files` |
| CVE-2021-23394 | `Studio-42/elFinder` | before 2.1.58 | tag `2.1.57` | Public PHP connector, writable root, `uploadDeny` including PHP types |
| CVE-2021-32682 | `Studio-42/elFinder` | through 2.1.58 | tags `2.1.58` and `2.1.59` | Retain both versions to isolate the individual 2.1.59 security patches before implementing active proof |
| CVE-2026-81891 | `Studio-42/elFinder` | before 2.1.70 | tags `2.1.69` and `2.1.70` | PHP `ZipArchive`, public connector, extraction enabled, writable root |

The Blueimp and elFinder repositories are public and can be checked out directly by tag. Preserve their default
sample configuration as a baseline, then document every web-server override separately.

## WordPress core

| CVE | WordPress versions required | Recommended vulnerable fixture | Notes |
|---|---|---:|---|
| CVE-2026-60137 | 6.8.0-6.8.5, 6.9.0-6.9.4, 7.0.0-7.0.1 | 6.9.4 | Keep 6.8.5 or 7.0.1 too if branch-specific regression coverage is desired |
| CVE-2026-63030 | 6.9.0-6.9.4, 7.0.0-7.0.1 | 7.0.1 (vuln, shared `labs/cve-2026-60137` image) + 7.0.2 control (`wordpress:7.0.2-php8.3-apache@sha256:62bce9e6…`, temp :8090 stack) | Nested batch request must reach the SQL timing sink; 7.0.2 answers the batch route but the timing differential is flat |
| CVE-2026-87902 | affected branch releases from 4.7.0 through 7.1.1 | 6.8.3 fixture already used | Requires a theme/page-template layout satisfying the vulnerable path; keep the working theme and database seed |
| CVE-2026-64638 | 4.7.0 through the branch-specific releases fixed in 4.7.34-7.0.3 | 7.0.2 (vuln, `wordpress:7.0.2-php8.3-apache`) + 7.0.3 control (`wordpress:7.0.3-php8.3-apache`), `labs/cve-2026-64638` | Inert `< area>` parser-differential marker posted to `/wp-login.php`; 7.0.2 normalizes it to a raw `<area>`, 7.0.3 escapes it. |
| CVE-2024-4439 | 6.0.x-6.5.1 branch backports (Avatar block XSS) | none (version detection only) | Passive advisory; the PoC is recorded as metadata but never sent automatically |
| WPVDB-df1ca42d / aa354358 / 5e9804e5 | branch-specific WPScan ranges (comment XSS, object injection) | none (version detection only) | WPScan IDs with no CVE; passive advisory, no fixture |

## WordPress plugins

| CVE | Plugin/archive | Vulnerable range | Recommended fixture | Availability/notes |
|---|---|---:|---:|---|
| CVE-2020-25213 | WP File Manager (`wp-file-manager`) | 6.0-6.8 | 6.8 | Free historical WordPress.org package |
| CVE-2020-35489 | Contact Form 7 (`contact-form-7`) | before 5.3.2 | 5.3.1 | Free historical package; retain a form/database seed |
| CVE-2023-28121 | WooPayments (`woocommerce-payments`) | affected unpatched branches from 4.8.0 through 6.3 | 5.6.1 | Also install a compatible WooCommerce version; keep activation/onboarding state |
| CVE-2023-32243 | Essential Addons for Elementor Lite | 5.4.0-5.7.1 | 5.7.1 | Install compatible free Elementor and enable registration prerequisites used by the advisory |
| CVE-2023-3460 | Ultimate Member | before 2.6.7 | 2.6.6 | Retain configured registration form and role settings |
| CVE-2024-10924 | Really Simple Security/SSL | 9.0.0-9.1.1.1 | 9.1.1.1 | Preserve plugin onboarding/security configuration |
| CVE-2024-28000 | LiteSpeed Cache | 1.9-6.3.0.1 | 6.3.0.1 | Some behavior depends on cache/debug configuration |
| CVE-2024-6220 | Keydatas (`keydatas`) | through 2.5.2 | SVN revision immediately before changeset 3127334 / version 2.5.2 | Free WordPress SVN source; record publishing password/configuration; active lab needs a controlled image source server. Sourcing note (2026-11-09): `downloads.wordpress.org/plugin/keydatas.2.5.2.zip` returns 404 and `plugins.trac.wordpress.org` currently serves a bot challenge, so the vulnerable branch is still unsourced. The current wordpress.org zip is 2.8.1 (patched; it rejects `..` URL segments in `keydatas_downloadImages()`). Keep the module passive-only until the pre-fix revision is obtained. |
| CVE-2026-1357 | WPvivid Backup & Migration (`wpvivid-backuprestore`) | through 0.9.123 | 0.9.123 (vuln) + 0.9.124 control (both retained `wpvivid-backuprestore.{0.9.123,0.9.124}.zip`) | WordPress 6.5/PHP 8.1 lab; seed pretty permalinks + www-data-owned wp-content + throwaway RSA api token (seed_token.py); stack caveat: backup dir .htaccess blocks reads, so the probe traverses to uploads/ for read-back |
| CVE-2026-1830 | Quick Playground (`quick-playground`) | through 1.3.1 | 1.3.1 (vuln) + 1.3.2 control (both retained `quick-playground.{1.3.1,1.3.2}.zip`) | BLOCKED: both versions fatal the whole WP bootstrap at plugins_loaded via is_plugin_active() (undefined outside admin) — verified HTTP 500 on every route on stock WP 6.5/PHP 8.1. No live lab; module is passive-only (readme.txt version). |
| CVE-2025-0818 | Filester | through 1.8.9 | 1.8.9 | Must configure its frontend/public elFinder feature |
| CVE-2025-0818 | Advanced File Manager | through 5.3.6 | 5.3.6 | Must configure its frontend/public elFinder feature |
| CVE-2025-0818 | File Manager Pro | through 8.4.2 | 8.4.2 | Commercial; must configure its frontend/public elFinder feature |
| CVE-2024-10547 | WP Membership | through 1.6.2 | 1.6.2 | Commercial CodeCanyon fixture needed; source is required to determine the real AJAX/multipart contract |
| CVE-2025-0357 | WPBookit Pro | through 1.6.9 | 1.6.9 | Commercial fixture needed; fixed in 1.6.10; source is required to determine the real request contract |
| CVE-2026-6692 | Slider Revolution (`revslider`) | 7.0.0-7.0.10 | 7.0.10 | Commercial; fixed in 7.0.11 |
| CVE-2026-92229 | Forminator (`forminator`) | through 1.57.2 | 1.57.2 (keep 1.57.3 as patched control) | Free WordPress.org package; seed a public knowledge quiz with a share-enabled network plus a page rendering it (see `labs/cve-2026-92229`) |
| CVE-2026-15748 | Forminator (`forminator`) | 1.18.1-1.56.1 | 1.56.1 (keep 1.56.2 as patched control) | Free WordPress.org package; seed a public custom form with a genuine upload field plus a select carrier (see `labs/cve-2026-15748`) |
| CVE-2026-18781 | Drag and Drop Multiple File Upload for Contact Form 7 | before 1.3.9.9 | 1.3.9.8 | Also install a compatible Contact Form 7 and create a form using the upload field |
| CVE-2026-32475 | Elementor Pro | through 4.2.1 | 4.2.1 | Commercial; also retain the matching free Elementor package and a configured vulnerable form/route |

For commercial plugins, obtain legitimate archives and do not commit them. A vulnerable archive plus its first
fixed release is ideal for differential testing.

## Joomla core

| CVE | Vulnerable range | Recommended Joomla fixture | Extra requirements |
|---|---:|---:|---|
| CVE-2010-4166 | Joomla 1.5.x through 1.5.21 | 1.5.21 (vuln, retained `Joomla_1.5.21-Stable-Full_Package.zip`) + 1.5.22 control (official full package, MD5 `71e57ac6fd588e4ac737a10e726f81e9`, retained) | Period stack: php:5.6-apache (ext/mysql+mysqli) + mysql:5.5; `com_weblinks` enabled via sample data (category id=2). Note: remote detector reads 1.5.15 from stale en-GB.xml; version.php is authoritative (1.5.21). |
| CVE-2015-8562 | Joomla 1.5.x, 2.x, and 3.x before 3.4.6 | 3.4.4 (`joomla_3.4.4_full.zip`, vendor download) + PHP 5.6.27 via joomla:3.6.3-apache image | Historical PHP session behavior matters; assert(string) must execute (PHP 5.x). See labs/cve-2015-8562/README.md for the Apache-NUL delivery analysis |
| CVE-2015-7297 | Joomla 3.2.0 through 3.4.4 | 3.4.4 (`joomla_3.4.4_full.zip`) + 3.4.5 control (`joomla_3.4.5_full.zip`), same PHP 5.6 runtime as CVE-2015-8562 | Unauthenticated `com_contenthistory` front-end route; advisory 20151001 also covers 7857/7858 |
| CVE-2015-7857 | Joomla 3.2.0 through 3.4.4 | 3.4.4 + 3.4.5 control (same archives) | Same `list[select]` sink; safe unknown-column differential |
| CVE-2015-7858 | Joomla 3.2.0 through 3.4.4 | 3.4.4 + 3.4.5 control (same archives) | Same sink; POST subquery-against-missing-table differential |
| CVE-2017-8917 | Joomla 3.7.0 | 3.7.0 | Core `com_fields` present |
| CVE-2018-15882 | before Joomla 3.8.12 | 3.8.11 | Upload surface and PHP PHAR support/configuration required for full reproduction |
| CVE-2018-6376 | 3.7.0 through 3.8.3 | 3.8.3 (vuln, archive-built PHP 7.1) + 3.8.11 control (official `joomla:3.8.11-apache` image) | Manager backend account; stock schema already carries the Hathor postinstall message (extension_id 700). Probe stores `admin_style[0]` via the profile form, then times the dashboard. |
| CVE-2026-73373 | 1.0.0-5.4.7 and 6.0.0-6.1.2 | 5.4.7 (vuln, `joomla:5.4.7-php8.3-apache@sha256:f8c0f159…`) + 5.4.8 control (`joomla:5.4.8-php8.3-apache@sha256:ce0c0ee3…`) | Convert Forms 5.0.4 upload field (images + shtml/shtm, allow_unsafe=0 so core isSafeFile runs) + Apache SSI for tmp/ via conf snippet. Vuln ceiling is VULNERABLE_UPLOAD_ONLY (#exec blocked in this container). |
| CVE-2026-92222 | 4.0.0-5.4.8 and 6.0.0-6.1.3 | 5.4.8 (vuln, `joomla:5.4.8-php8.3-apache@sha256:ce0c0ee3…`) + 5.4.9 control (`joomla:5.4.9-php8.3-apache@sha256:8b2b8dd0…`) | Published public newsfeed storing a `file://` marker link (admin form flow; default Uncategorised com_newsfeeds category id 5); internal-only gopher listener service for the transport differential. 5.4.9 adds `schemes="http,https"` to the link field + scheduler task URL. |
| CVE-2026-92227 | Joomla 4.0.0-5.4.8 and 6.0.0-6.1.3 (PR:N/AT:P) | 5.4.8 (vuln, same digest as above) + 5.4.9 control (same digest as above) | Victim user + TOTP MFA record + com_users silent-login options seeded via SQL; cookie plugin on by default. Probe needs victim creds via --aggressive-arg. |
| CVE-2026-48897 | Joomla 4.0.0-5.4.5 and 6.0.0-6.1.0 | 5.4.5 (vuln, `joomla:5.4.5-php8.3-apache@sha256:d1ab9e1b…`) + 5.4.8 control (same digest as above) | TOTP-enrolled victim + a no-MFA account. Probe logs in as the no-MFA user (sets `mfa_checked=1`), then as the victim in the same session with `remember=0`. |
| CVE-2026-90907 | Joomla 1.5.0-5.4.8 and 6.0.0-6.1.3 | 5.4.8 (vuln, `joomla:5.4.8-php8.3-apache@sha256:ce0c0ee3…`) + 5.4.9 control (same digest as above) | Registration off and `change_login_name=1`; probe posts `profile.save` as a guest and reads the created `user_id` from the redirect. |
| CVE-2025-25227 | Joomla 4.0.0-4.4.12 and 5.0.0-5.2.5 | 5.2.5 (vuln, `joomla:5.2.5-php8.3-apache@sha256:1b059a09…`) + 5.2.6 control (`joomla:5.2.6-php8.3-apache@sha256:de29819c…`) | TOTP-enrolled victim; probe logs in with the password and requests `task=method.add`. |
| CVE-2026-72531 | Joomla 4.0.0-5.4.7 and 6.0.0-6.1.2 | 5.4.7 (vuln, `joomla:5.4.7-php8.3-apache@sha256:63a884c5…`) + 5.4.8 control | Author API token + `core.login.api`; passive-only (the field-creation POST body shape is still pending). |
| CVE-2026-71573 | Joomla 4.0.0-5.4.7 and 6.0.0-6.1.2 | 5.4.7 (vuln, same digest as above) + 5.4.8 control | CORS enabled with a non-wildcard whitelist in `configuration.php` + an admin API token; probe reflects an untrusted Origin on an authenticated GET. |
| CVE-2017-14596 | Joomla before 3.8.0 | none (needs an LDAP server fixture) | LDAP authentication plugin; passive-only version/code-path check. |

Old Joomla releases should use dedicated images rather than forcing incompatible versions into one shared image.

## Joomla extensions

| CVE | Extension/archive | Vulnerable range | Recommended fixture | Notes |
|---|---|---:|---:|---|
| CVE-2026-56292 | AcyMailing Enterprise | 6.0.0-10.11.0 | 10.10.2 (`acymailing_enterprise_v10.10.2`, package tree with sub-zips) + 11.1.1 control (`acymailing_enterprise_v11.1.1_joomla`) | Joomla 5.2.5/PHP 8.3; disable SEF so `index.php?option=com_acym&ctrl=frontentityselect...` is reachable; `join=` is required by the PHP 8 signature |
| CVE-2026-94132 | AcyMailing Enterprise | 1.0.0-11.0.5 | 11.0.5 (`acymailing_enterprise_v11.0.5`) + 11.1.1 control | Full lab chain in `labs/cve-2026-94132`: GreenMail POP3, `connection_method=pear`, forward action, malicious `image/png` part named `proofcms_94132.php`, cron trigger; 11.0.5 writes and executes the PHP file, 11.1.1 rejects the extension |
| CVE-2024-40744 | Convert Forms | before 4.4.6 (extension check missing; NVD/vendor cite before 4.4.8, which also fixed the companion XSS) | 4.4.5 (`convert_forms_4.4.5_free.zip`, official Tassos release) + fixed control 4.4.6 (`convert_forms_4.4.6_free.zip`) | Public form with a File Upload field (`image/*` + allow-unsafe, per the validated PoC config); see `labs/cve-2024-40744` |
| CVE-2025-26854 | Articles Good Search | 1.0.0-1.2.4.0011 | 1.2.4.0011 | Retain component/plugin package and a searchable article dataset |
| CVE-2026-21627 | `plg_system_nrframework` / Tassos Framework | 4.10.14-6.0.37 | 6.0.15 via Convert Forms 5.0.4 (validated lab) | Fixed control: 6.0.38 via Convert Forms 5.1.0 free (`convert_forms_5.1.0_free.zip`, vendor download) |
| CVE-2026-21627 | Convert Forms | 3.2.12-5.1.0 product range reported | Prefer a package bundling nrframework 6.0.2 | Keep the exact bundled framework version |
| CVE-2026-21627 | EngageBox | 6.0.0-7.1.0 product range reported | Any package bundling affected nrframework | Optional alternative fixture |
| CVE-2026-21627 | Google Structured Data | 5.1.7-6.1.0 product range reported | Any package bundling affected nrframework | Optional alternative fixture |
| CVE-2026-21627 | Advanced Custom Fields | 2.2.0-3.1.0 product range reported | Any package bundling affected nrframework | Optional alternative fixture |
| CVE-2026-21627 | Smile Pack / MailChimp Auto-Subscribe | affected releases bundling nrframework | Exact archive containing nrframework 4.10.14-6.0.37 | Optional; record bundled framework version rather than inferring it from product name |
| CVE-2026-48907 | JCE Editor | before 2.9.99.5 | 2.9.99.1 (`jce-2.9.99.1`, installer layout) + fixed control 2.9.99.13 (`jce-2.9.99.13`) | Anonymous profiles.import surface; no form/menu seeding needed (CSRF token from any public page) |
| CVE-2026-48908 | SP Page Builder | 1.0.0-6.6.1 | 6.6.1 | Commercial/current distribution may require a legitimate archive |
| CVE-2026-48939 | iCagenda | 3.2.1-3.9.14 and 4.0.0-4.0.7 (RCE transition needs Joomla 6.0.0-6.1.1; older Joomla cores block via safe-file checks) | 4.0.7 (`icagenda_4.0.7_package.zip`, official JoomliC Core) + fixed control 4.0.8 (`icagenda_4.0.8_package.zip`) on Joomla 6.1.0-rc1 (`joomla:6.1-rc-apache` digest-pinned) | 4.x needs a public submit menu item (guest submitAccess) + one event category; 3.x branch (3.9.15 fixed) uses different controllers and is core-blocked on old Joomla |
| CVE-2026-49049 | Helix3 Framework | 1.0-3.1.0 | 2.2 (`Helix3-2.2`, installer layout) + J3 security-patch control (`Helix3-j3-security`, git tag j3-security-v1.0.0) | Joomla 3.10/PHP 7.4 stack (`joomla:3.10-php7.4-apache` digest-pinned); endpoint needs no form/menu, CSRF token not required pre-fix |
| CVE-2026-56290 | Page Builder CK | through 3.5.10 (fixed 3.6.0; J3 line fixed 3.1.1; J4 line fixed 3.4.10) | 3.5.4 Pro (vuln, `pagebuilderck-pro 3.5.4/` extracted tree) + 3.6.7 Light control (`pagebuilderck-light 3.6.7/` tree) + 3.1.4 J3 tree (`pagebuilderck-light_3.1.4.j3/`, above the J3 backport) | Joomla 5.2.3/PHP 8.3 lab; stack caveat: framework isSafeFile input gate blocks literal .php, so the lab ceiling is marker-based VULNERABLE_UPLOAD_ONLY |
| CVE-2026-56291 | Balbooa Forms | through 2.4.0 (fixed 2.4.1; min safe now 2.4.3.2 per vendor) | 2.4.0 (vuln, `balbooa_forms_2.4.0/` extracted tree with packages/) + 2.4.3.1 control (`Balbooa Forms Builder Pro 2.4.3.1/` tree) | Joomla 5.2.3/PHP 8.3 lab; stack caveat: framework isSafeFile input gate blocks literal .php, so the lab ceiling is marker-based VULNERABLE_UPLOAD_ONLY (component gate fully missing in 2.4.0) |
| CVE-2026-57827 | RSFiles! | before 1.17.12 | 1.16.29 (vuln tree) + 1.17.12 control (extracted tree `RSFiles! 1.17.12/`, installable `component/com_rsfiles-v1.17.12.zip`) | Joomla 3.9.10 lab; 1.17.12 adds `$this->checkToken()` to `site/controllers/rsfiles.php::upload()` |
| CVE-2026-57829 | Helix Ultimate | through 2.2.6 (stored XSS via saveMegaMenuSettings) | 1.1.4 (`helix-ultimate-1.1.4`, installer layout) — safe probe is reachability-only by design (no state-changing write), so the lab ceiling is BLOCKED_EXTERNAL | Same Joomla 3.10 lab as CVE-2026-57830; no form/menu needed |
| CVE-2026-57830 | Helix Ultimate | through 2.2.6 (media manager via helix=ultimate AJAX) | 1.1.4 (vuln) + j3-security-v1.0.0 control (`plg_system_helixultimate_j3_v2.1.4-j3sec.zip` + extracted tree, GitHub release asset) on Joomla 3.10/PHP 7.4 | Same lab as above: unauthenticated, token from any public page; the com_ajax plugin= route never dispatches on this branch |
| CVE-2026-78079 | Helix Ultimate | 1.0-2.2.9 | 2.2.4 plugin source (`helix-ultimate-2.2.4`, Composer vendor built at seed time) + 2.2.10 control (`helix-ultimate-2.2.10`, vendor included) | Joomla 5.2.5/PHP 8.3; requires a front-end login because the redirect only fires for an authenticated identity. Keep 2.2.6 too if sharing with CVE-2026-57830 |
| CVE-2026-61424 | DJ-Classifieds | before 3.11.2 | 3.11.1 (vuln, `djclassifieds_3.11.1.zip` bundle holding installable inner `pkg_djclassifieds_3.11.1.zip`) + 3.11.2 control (extracted tree `djclassifieds_3.11.2/`, 22 entries with pkg manifest; Session::checkToken gate verified) | Joomla 5.2.3/PHP 8.3 lab; probe uploads a valid 1x1 GIF + marker (clear of the 3-string scan) with name+filename fields; public read-back from /tmp/djupload/; proof files are proofcms_*.gif |
| CVE-2026-61425 | Gridbox | 1.0.0-2.20.0.2 | 2.20.0.2 (vuln, retained package tree) + 2.20.5.0 control (vendor update endpoint, sha512-pinned) | Joomla 5.2.3; Gridbox system plugin enabled. Probe needs only the target username (`admin_user`, default admin). |
| CVE-2026-65884 | Gridbox | 1.0.0-2.20.1 | 2.20.0.2 (vuln, shared lab) + 2.20.5.0 control | Store checkout registration enabled by default; probe is anonymous and uses `groups[]=7`. |
| CVE-2026-65885 | Gridbox | 1.0.0-2.20.1 | 2.20.0.2 (vuln, shared lab) + 2.20.5.0 control | Frontend account with `core.create`; probe uploads an inert `.shtml` marker and reads it back. |
| CVE-2026-65886 | Gridbox | 1.0.0-2.20.1 | 2.20.0.2 (vuln, shared lab) + 2.20.5.0 control | Unauthenticated `uploader.showImage`; probe checks structural markers only. |
| CVE-2026-65887 | Gridbox | 1.0.0-2.20.1 | 2.20.0.2 (vuln, shared lab) + 2.20.5.0 control | Non-super victim (`labvictim`); mail sink `sendmail_path=/bin/true` so the token leak completes. |
| CVE-2026-65888 | Gridbox | 1.0.0-2.20.1 | 2.20.0.2 (vuln, shared lab) + 2.20.5.0 control | Unauthenticated `account.socialLogin`; probe needs the victim email (admin `lab@example.test` in the lab). |
| CVE-2026-65889 | Gridbox | 1.0.0-2.20.1 | 2.20.0.2 (vuln, shared lab) + 2.20.5.0 control | Seed plants `tmp/gb-delete-canary`; probe deletes it via `editor.generateNewApp` and checks the marker over HTTP. |
| CVE-2026-65890 | Gridbox | 1.0.0-2.20.1 | 2.20.0.2 (vuln, shared lab) + 2.20.5.0 control | Seed plants page 900001 + one approved comment; probe uses a boolean differential only. |
| CVE-2026-65947 | Gridbox | 1.0.0-2.20.1 | 2.20.0.2 (vuln, shared lab) + 2.20.5.0 control | Administrator session; probe uses a reversible tokenless publish/unpublish on page 900001. |
| CVE-2026-102784 | Gridbox | 2.20.2-2.20.3.1 | none (no 2.20.2/2.20.3.1 fixture) | Passive-only; the `addLanguage` path reaches Joomla's package installer and is not safely triggerable. |
| CVE-2026-105607 | Gridbox | 1.0.0-2.20.4.2 | 2.20.0.2 (vuln, shared lab) + 2.20.5.0 control | Guest comment/review cookie; page 900001; probe stores an inert marker and checks the recent comments/reviews widgets. |
| CVE-2026-107903 | Gridbox | 1.0.0-2.20.4.2 | 2.20.0.2 (vuln, shared lab) + 2.20.5.0 control | Guest review; `reviews.getReviewById`; marker is checked in the `comment` field (no script executed). |
| CVE-2026-76570 | JCTables (`com_jctables`) | 1.0.0 through 1.20.0 (fixed 1.21.1) | ≤1.20.0 NEEDED (vendor + JED carry only current 1.21.x; old builds not publicly archived) + 1.21.x control | Safe probe is a read-only boolean-blind getrow differential (no data read or written); lab needs a Joomla + JCTables with a frontend table (mid/tid swept 1-7/0-3) |
| CVE-2019-19576 | K2 | before 2.27 | 2.8.0 (CVE-reported release; git-sourced tree `K2_v2.8.0` from getk2/k2 commit e6b875ef) + Joomla 3.6.3/PHP 5.6.27 | Backend item-save needs an admin session (lab admin/admin); fixed control 2.28 (`K2_v2.28`). Note: 2.11.20240911 still stores plain .phar (model file_new_name_ext defeats the lib rename) — not a valid control. 2.6.8 unusable on PHP 5.6+ (pre-PCRE-safe Verot: all uploads fail MIME detection) |
| CVE-2019-19634 | K2 | before 2.28 | 2.8.0 (same fixture as CVE-2019-19576) | .pht additionally requires the aligned block lists (2.27 still serves .pht); same backend flow and control |
| PROOFCMS-K2-REGISTRATION-AVATAR | K2 user-profile integration | public registration surface | none (detection only) | Companion surface probe for CVE-2019-19576/19634; needs Joomla + K2 with public registration enabled, no package to retain |

The 3.11.1 bundle (`djclassifieds_3.11.1.zip`, outer bundle holding the installable
inner `pkg_djclassifieds_3.11.1.zip`) and the 3.11.2 extracted tree
(`djclassifieds_3.11.2/`, 22 entries with the package manifest) are retained
for CVE-2026-61424 (see the active-probes table).

## Node.js runtime labs

| CVE | Component | Affected range | Recommended fixture | Notes |
|---|---|---:|---:|---|
| CVE-2026-111497 | Node.js bundled Brotli decoder | 22.x <22.23.4, 24.x <24.22.1, 26.x <26.12.1; EOL lines | 24.22.0 (vuln, `node:24.22.0`) + 24.22.1 control (`node:24.22.1`), `labs/cve-2026-111497` | Safe malformed block-switch vector; vulnerable reports `BLOCK_LENGTH_1`, patched reports `BLOCK_SWITCH`. No OOB/RCE stream is sent. |

## ASP.NET Core runtime labs

| CVE | Runtime required | Recommended fixture | Host/configuration requirements |
|---|---|---:|---|
| CVE-2025-55315 | ASP.NET Core 2.3 <2.3.6, 8.0 <8.0.21, 9.0 <9.0.10 | 8.0.20 (vuln, `mcr.microsoft.com/dotnet/aspnet:8.0.20`) + 8.0.21 control, `labs/cve-2025-55315` | Minimal `net8.0` app; raw-TCP chunk-extension differential. No smuggled request is sent. |
| CVE-2026-102870 | ASP.NET Core 10.0.0-10.0.12 / 11.0.0-preview Blazor WebAssembly server package | none | Requires the Blazor WebAssembly debug proxy and a browser debugger session; passive version check only. |
| CVE-2026-88092 | ASP.NET Core 8.0 <8.0.32, 9.0 <9.0.21, 10.0 <10.0.13 | none | Different request-smuggling variant from CVE-2025-55315; no safe wire differential yet. |
| CVE-2010-3332 | ASP.NET 1.1 SP1, 2.0 SP1/SP2, 3.5, 3.5.1, 4.0 without MS10-070 | none (Windows/IIS .NET 2.0) | Padding oracle; the module now requires a ScriptResource/WebResource/ViewState surface before reporting. the target `/portal/login.aspx` sends the 2.0.50727 header but exposes no `.axd`/ViewState, so the result is INCONCLUSIVE; `/app/` exposes no version. |
| CVE-2011-3416 | ASP.NET 1.1 SP1, 2.0 SP2, 3.5 SP1, 3.5.1, 4.0 without MS11-100 | none (Windows/IIS .NET 2.0 + login flow) | Forms Authentication null-byte bypass; passive surface check requires `.ASPXAUTH`/FormsAuthentication. the target `/portal/` uses GeneXus SSO, so NOT_AFFECTED. |
| CVE-2024-2961 | PHP 5.6.0-8.3.6 with glibc <=2.39 | 8.3.4 (vuln, `vulhub/php:8.3.4-apache`, glibc 2.36) + 8.4.27 control (`php:8.4-apache`, glibc 2.41), `labs/cve-2024-2961` | Deliberate `file_get_contents` sink; safe base64 `/etc/passwd` read through `php://filter`. Full iconv RCE chain is the public `cnext-exploit.py`. |
| CVE-2023-6553 | Backup Migration 1.0.8-1.3.7 | 1.3.7 (vuln) + 1.3.8 control, `labs/cve-2023-6553` | WordPress 6.4.3 + plugin, installed with WP-CLI; plugin archives fetched at build time. Safe `Content-Dir` filter-chain `sleep(0)`/`sleep(4)` differential. |
| CVE-2024-8929 | PHP 8.1 <8.1.31, 8.2 <8.2.26, 8.3 <8.3.14 | 8.3.13 (vuln) + 8.3.14 control, `labs/cve-2024-8929` | Official GHSA fake MySQL server + mysqli client; `docker compose run --rm vuln/patched`; one-shot CLI, no published ports. |
| CVE-2023-3824 | PHP 8.0 <8.0.30, 8.1 <8.1.22, 8.2 <8.2.8 | 8.2.7 (vuln) + 8.2.9 control, `labs/cve-2023-3824` | Crafted phar with 4095/4096-byte entry names; `docker compose run --rm vuln/patched`; one-shot CLI, no published ports. |
| CVE-2024-8932 | PHP 8.1 <8.1.31, 8.2 <8.2.26, 8.3 <8.3.14 (32-bit) | 8.3.13 i386 (vuln) + 8.3.14 control, `labs/cve-2024-8932` | i386 PHP CLI + ldap; 1,431,655,766-byte input; one-shot CLI, no published ports. |
| CVE-2023-3823 | PHP 8.0 <8.0.30, 8.1 <8.1.22, 8.2 <8.2.8 | none (Apache mod_php + flaky global-state pollution; CLI/FPM do not reproduce) | Passive version check; upstream regression test uses the test-only zend-test override. |
| CVE-2024-1071 | Ultimate Member 2.1.3-2.8.2 | 2.8.2 (vuln) + 2.8.3 control, `labs/cve-2024-1071` | WordPress 6.4.3 + plugin; own-table directory mode; seeded member so ORDER BY evaluates; safe constant-sleep differential. |
| CVE-2023-28121 | WooPayments 4.8.0-6.3.x | 5.6.1 (vuln) + 5.6.2 control, `labs/cve-2023-28121` | WordPress 6.4.3 + WooCommerce 8.6.1; safe REST header differential; no state change. |
| CVE-2024-27956 | WP Automatic through 3.92.0 | 3.92.0 (vuln), `labs/cve-2024-27956` | WordPress 6.4.3 + plugin; package fetched at build time from the public PoC mirror because WordPress.org removed it. Safe `auth=%00` constant-sleep SQL differential. |

## PHP runtime labs

| CVE | Runtime required | Recommended fixture | Host/configuration requirements |
|---|---|---:|---|
| CVE-2012-1823 | PHP-CGI before 5.3.13 or 5.4.0-5.4.2 | PHP 5.3.12 built from museum source (`labs/cve-2012-1823` Dockerfile; verified sha256 `483a7368db1d2f7b87977b90b1c04bbefbd2201849d45d6cc0703366396ef124`) | Apache Action/AddHandler CGI mapping (no mod_php); control = same binary without the mapping |
| CVE-2019-11043 | PHP-FPM 7.3 <7.3.11 with vulnerable nginx config | PHP 7.3.10 FPM + nginx (labs/cve-2019-11043), single static worker | Single static worker (pm.max_children=1); phuip-fpizdam detects the target and finds attack params, but the attack phase hangs and the marker does not execute |
| CVE-2024-4577 | Windows PHP-CGI; unsupported branches or 8.1 before 8.1.29, 8.2 before 8.2.20, 8.3 before 8.3.8 | PHP 8.2.19 plus 8.2.20 control | Requires Windows, Apache/IIS CGI, and an affected Windows Best-Fit code page. A normal Linux Docker container cannot reproduce it; use an isolated Windows VM or Windows-container host |
| CVE-2026-109618 | PHP 8.2 before 8.2.35, 8.3 before 8.3.36, 8.4 before 8.4.27, 8.5 before 8.5.12 | lab `labs/cve-2026-109618` (PHP 8.3.35 image + single-worker + 16M OOM geometry) | Aggressive OOM crash differential; keep the 8.3.36 image as patched control |
| CVE-2026-109619 | same ranges as CVE-2026-109618 | lab \labs/cve-2026-109619\ (PHP 8.2.34 mod_php + single worker + generated 1MB cookie_path) + lab \labs/cve-2026-109619-cli\ (PHP 8.3.35 cli-server, single process) | Aggressive OOM-gate differential (mod_php); safe stale-PSID leak differential 4096B vs 32B cookie (cli-server); filename-poison tested on both 8.2.34 and fixed — app-level primitive, deliberately not shipped |

## Passive platform advisories (version/config detection only — no fixture)

| CVE | Component | What blocks active proof |
|---|---|---|
| CVE-2018-8284 / CVE-2023-21722 / CVE-2023-36560 / CVE-2023-36899 | .NET Framework / ASP.NET | Passive version detection only: exact servicing build + Windows/IIS prerequisites required; no lab harness. |
| CVE-2026-42945 / CVE-2026-9256 | NGINX rewrite module | Passive version/config detection only: needs a vulnerable rewrite directive sequence; memory-corruption proof has no safe lab harness. |
| CVE-2026-42530 / CVE-2026-90439 | NGINX HTTP/3 module | Passive version/config detection only: needs HTTP/3 + `ngx_http_v3_module`; no safe lab harness. |
| CVE-2026-42055 | NGINX proxy-v2 / gRPC modules | Passive version/config detection only: needs proxy-v2 or gRPC configuration; no safe lab harness. |
| CVE-2026-42533 | NGINX map-regex | Passive version/config detection only: needs a vulnerable map regex; no safe lab harness. |
| CVE-2024-58288 | GeneXus Protection Server | Windows service unquoted-path local privilege escalation: needs a Windows host and the 9.7.2.10 installer; no Linux web harness. |
| CVE-2026-56434 / CVE-2026-60005 | NGINX SSI / slice modules | Passive version/config detection only: needs the respective module configured; no safe lab harness. |

## Shared infrastructure to retain

- WordPress images/source archives for the exact core branches above.
- Joomla full packages for 1.5.21, 3.4.5, 3.7.0, 3.8.11, 3.10.x, 5.4.7, and optionally 6.1.2.
- MariaDB/MySQL images compatible with each historical CMS generation.
- Apache/PHP and Nginx/PHP-FPM images pinned by digest where possible.
- A tiny controlled HTTP image server for Keydatas remote-download tests.
- Mail capture only when a plugin setup flow requires it; do not expose labs publicly.
- Per-lab SQL/database seeds, uploaded-media seeds, and configuration scripts.
- Fixed-version control packages for every active differential proof.

## Storage layout on this workstation

Docker Desktop's data VHD was migrated on 2026-10-01 to:

```text
D:\DockerDesktopData\wsl\disk\docker_data.vhdx
```

The original Docker Desktop path remains a directory junction:

```text
C:\Users\micha\AppData\Local\Docker\wsl\disk
    -> D:\DockerDesktopData\wsl\disk
```

Keep acquired plugin archives in a separate development fixture tree on `D:`. Do not place them inside the Git
repository or directly inside Docker's VHD. A suggested layout is:

```text
D:\ProofCMS-Labs\
├── archives\joomla\
├── archives\wordpress\
├── archives\generic\
├── checksums\
├── compose\
├── databases\
└── notes\
```
