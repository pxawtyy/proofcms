#Requires -Version 5.1
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

foreach ($s in @(
    @{ Cli = 'cli-vuln'; Url = 'http://127.0.0.1:9220'; Title = 'WP 7.1.0 XSS Lab' },
    @{ Cli = 'cli-fixed'; Url = 'http://127.0.0.1:9221'; Title = 'WP 7.1.1 XSS Lab' }
)) {
    $cli = "proofcms-wpvdb-aa354358-$($s.Cli)-1"
    $installed = $false
    try {
        $r = Invoke-WebRequest -Uri $s.Url -UseBasicParsing -TimeoutSec 20
        $installed = ($r.StatusCode -eq 200)
    } catch {
        $installed = $false
    }
    if ($installed) {
        Write-Host "$($s.Cli): already installed"
        continue
    }
    docker exec $cli wp core install --url=$($s.Url) --title="$($s.Title)" --admin_user=admin --admin_password=proofcms-lab-password --admin_email=admin@example.test --skip-email --allow-root 2>&1 | Out-Null
    docker exec $cli wp option update comment_moderation 0 --allow-root 2>&1 | Out-Null
    docker exec $cli wp option update comment_whitelist 0 --allow-root 2>&1 | Out-Null
    docker exec $cli wp option update comments_notify 0 --allow-root 2>&1 | Out-Null
    docker exec $cli wp post create --post_type=post --post_status=publish --post_title='ProofCMS Comment Lab' --post_content='Lab post for comment rendering.' --allow-root 2>&1 | Out-Null
    Write-Host "$($s.Cli): installed"
}
