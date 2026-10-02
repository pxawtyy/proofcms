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
| CVE-2026-63030 | 6.9.0-6.9.4, 7.0.0-7.0.1 | 6.9.4 | Same image can cover the `wp2shell` chain with CVE-2026-60137 |
| CVE-2026-87902 | affected branch releases from 4.7.0 through 7.1.1 | 6.8.3 fixture already used | Requires a theme/page-template layout satisfying the vulnerable path; keep the working theme and database seed |

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
| CVE-2024-6220 | Keydatas (`keydatas`) | through 2.5.2 | SVN revision immediately before changeset 3127334 / version 2.5.2 | Free WordPress SVN source; record publishing password/configuration; active lab needs a controlled image source server |
| CVE-2025-0818 | Filester | through 1.8.9 | 1.8.9 | Must configure its frontend/public elFinder feature |
| CVE-2025-0818 | Advanced File Manager | through 5.3.6 | 5.3.6 | Must configure its frontend/public elFinder feature |
| CVE-2025-0818 | File Manager Pro | through 8.4.2 | 8.4.2 | Commercial; must configure its frontend/public elFinder feature |
| CVE-2024-10547 | WP Membership | through 1.6.2 | 1.6.2 | Commercial CodeCanyon fixture needed; source is required to determine the real AJAX/multipart contract |
| CVE-2025-0357 | WPBookit Pro | through 1.6.9 | 1.6.9 | Commercial fixture needed; fixed in 1.6.10; source is required to determine the real request contract |
| CVE-2026-6692 | Slider Revolution (`revslider`) | 7.0.0-7.0.10 | 7.0.10 | Commercial; fixed in 7.0.11 |
| CVE-2026-18781 | Drag and Drop Multiple File Upload for Contact Form 7 | before 1.3.9.9 | 1.3.9.8 | Also install a compatible Contact Form 7 and create a form using the upload field |
| CVE-2026-32475 | Elementor Pro | through 4.2.1 | 4.2.1 | Commercial; also retain the matching free Elementor package and a configured vulnerable form/route |

For commercial plugins, obtain legitimate archives and do not commit them. A vulnerable archive plus its first
fixed release is ideal for differential testing.

## Joomla core

| CVE | Vulnerable range | Recommended Joomla fixture | Extra requirements |
|---|---:|---:|---|
| CVE-2010-4166 | Joomla 1.5.x through 1.5.21 | 1.5.21 | PHP/MySQL versions old enough to run Joomla 1.5; `com_weblinks` enabled |
| CVE-2015-8562 | Joomla 1.5.x, 2.x, and 3.x before 3.4.6 | 3.4.5 | Historical PHP session behavior matters; use the PHP version required by the original PoC |
| CVE-2017-8917 | Joomla 3.7.0 | 3.7.0 | Core `com_fields` present |
| CVE-2018-15882 | before Joomla 3.8.12 | 3.8.11 | Upload surface and PHP PHAR support/configuration required for full reproduction |
| CVE-2026-73373 | 1.0.0-5.4.7 and 6.0.0-6.1.2 | 5.4.7 and optionally 6.1.2 | Needs an accessible upload surface; current ProofCMS proof can use a Convert Forms upload field; SSI execution additionally requires server SSI configuration |

Old Joomla releases should use dedicated images rather than forcing incompatible versions into one shared image.

## Joomla extensions

| CVE | Extension/archive | Vulnerable range | Recommended fixture | Notes |
|---|---|---:|---:|---|
| CVE-2024-40744 | Convert Forms | before 4.4.8 | 3.2.9 or 3.2.12 already available | Create a public form with a file-upload field |
| CVE-2025-26854 | Articles Good Search | 1.0.0-1.2.4.0011 | 1.2.4.0011 | Retain component/plugin package and a searchable article dataset |
| CVE-2026-21627 | `plg_system_nrframework` / Tassos Framework | 4.10.14-6.0.37 | 6.0.2 preferred | Can come bundled with affected Convert Forms, EngageBox, Google Structured Data, Advanced Custom Fields, Smile Pack, or MailChimp Auto-Subscribe; the existing 4.9.62 fixture is below the affected range and cannot reproduce this CVE |
| CVE-2026-21627 | Convert Forms | 3.2.12-5.1.0 product range reported | Prefer a package bundling nrframework 6.0.2 | Keep the exact bundled framework version |
| CVE-2026-21627 | EngageBox | 6.0.0-7.1.0 product range reported | Any package bundling affected nrframework | Optional alternative fixture |
| CVE-2026-21627 | Google Structured Data | 5.1.7-6.1.0 product range reported | Any package bundling affected nrframework | Optional alternative fixture |
| CVE-2026-21627 | Advanced Custom Fields | 2.2.0-3.1.0 product range reported | Any package bundling affected nrframework | Optional alternative fixture |
| CVE-2026-21627 | Smile Pack / MailChimp Auto-Subscribe | affected releases bundling nrframework | Exact archive containing nrframework 4.10.14-6.0.37 | Optional; record bundled framework version rather than inferring it from product name |
| CVE-2026-48907 | JCE Editor | before 2.9.99.5 | 2.9.99.4, or existing 2.7.17 | Configure the upload route required by the proof |
| CVE-2026-48908 | SP Page Builder | 1.0.0-6.6.1 | 6.6.1 | Commercial/current distribution may require a legitimate archive |
| CVE-2026-48939 | iCagenda | 3.2.1-3.9.14 and 4.0.0-4.0.7 | 3.9.14 and 4.0.7 | Keep both branch endpoints if testing boundary behavior |
| CVE-2026-49049 | Helix3 Framework | 1.0-3.1.0 | 3.1.0 | Install compatible Helix3 template/framework and expose `com_ajax` |
| CVE-2026-56290 | Page Builder CK | reported legacy 1.x/2.x and affected 3.x builds | Exact PoC-confirmed vulnerable archive | Public range is still ambiguous; retain source and build identifier |
| CVE-2026-56291 | Balbooa Forms | through 2.4.0 | 2.4.0 | Create a public form/upload route |
| CVE-2026-57827 | RSFiles! | before 1.17.12 | 1.17.11 | Commercial archive likely required |
| CVE-2026-57830 | Helix Ultimate | through 2.2.6 | 2.2.6 | Covers deletion module; use disposable files only |
| CVE-2026-78079 | Helix Ultimate | 1.0-2.2.9 | 2.2.9 | Keep 2.2.6 too if sharing with CVE-2026-57830 |
| CVE-2026-61424 | DJ-Classifieds | before 3.11.2 | 3.11.1 | Commercial archive likely required; configure public upload flow |

The current `dj_classifieds_3.11` archive on this workstation is not an installable extension: it contains only
eight XML data/export files and no PHP code or Joomla package manifest. A complete DJ-Classifieds 3.11.1 installer
is still required for CVE-2026-61424.

## PHP runtime labs

| CVE | Runtime required | Recommended fixture | Host/configuration requirements |
|---|---|---:|---|
| CVE-2012-1823 | PHP-CGI before 5.3.13 or 5.4.0-5.4.2 | PHP 5.4.2 | Apache CGI mapping; do not use mod_php or PHP-FPM |
| CVE-2019-11043 | PHP-FPM 7.1 before 7.1.33, 7.2 before 7.2.24, or 7.3 before 7.3.11 | PHP-FPM 7.3.10 | Nginx with the historically vulnerable `fastcgi_split_path_info`/`PATH_INFO` configuration; isolate because active historical PoCs can crash workers |
| CVE-2024-4577 | Windows PHP-CGI; unsupported branches or 8.1 before 8.1.29, 8.2 before 8.2.20, 8.3 before 8.3.8 | PHP 8.2.19 plus 8.2.20 control | Requires Windows, Apache/IIS CGI, and an affected Windows Best-Fit code page. A normal Linux Docker container cannot reproduce it; use an isolated Windows VM or Windows-container host |

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
