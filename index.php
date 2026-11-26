<?php
// Educational SQL injection scanner - professional dashboard UI. Lab targets only.
require_once __DIR__ . '/auth.php';
require_login();

const ERROR_SIGNATURES = [
    'you have an error in your sql syntax', 'warning: mysql', 'mysqli_', 'unclosed quotation mark',
    'quoted string not properly terminated', 'pg_query', 'sqlite3::', 'sqlstate', 'odbc', 'syntax error'
];
const SEVERITY = ['Boolean-based' => 'Critical', 'Error-based' => 'High', 'Time-based' => 'High'];
const WEIGHT   = ['Critical' => 45, 'High' => 30];
const TYPE_COLOR = ['Error-based' => '#FF5A5A', 'Boolean-based' => '#2EE57A', 'Time-based' => '#F5C84B'];


function icon(string $n): string {
    $p = [
        'grid'  => '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
        'scan'  => '<circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/>',
        'clock' => '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
        'shield'=> '<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6l8-3z"/>',
        'bug'   => '<path d="M9 9h6v6a3 3 0 0 1-6 0V9zM9 5l1.5 2M15 5l-1.5 2M4 12h5M15 12h5M5 18l4-2M19 18l-4-2"/>',
        'layers'=> '<path d="M12 3l9 5-9 5-9-5 9-5zM3 13l9 5 9-5"/>',
        'send'  => '<path d="M22 2L11 13M22 2l-7 20-4-9-9-4 20-7z"/>',
        'down'  => '<path d="M12 4v11m0 0l-4-4m4 4l4-4M5 20h14"/>',
    ];
    return '<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">' . ($p[$n] ?? '') . '</svg>';
}

function is_lab_target(string $url): bool {
    $host = parse_url($url, PHP_URL_HOST);
    if (!$host) return false;
    $ip = gethostbyname($host);
    return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false;
}

function fetch(string $url, string $cookie = ''): array {
    $GLOBALS['reqs'] = ($GLOBALS['reqs'] ?? 0) + 1;
    $ch = curl_init($url);
    $opts = [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 15, CURLOPT_FOLLOWLOCATION => false];
    if ($cookie !== '') $opts[CURLOPT_COOKIE] = $cookie;
    curl_setopt_array($ch, $opts);
    $start = microtime(true);
    $body = curl_exec($ch);
    $time = microtime(true) - $start;
    curl_close($ch);
    return [$body === false ? '' : $body, $time];
}

function with_param(string $url, string $param, string $value): string {
    $p = parse_url($url);
    parse_str($p['query'] ?? '', $q);
    $q[$param] = $value;
    $base = $p['scheme'] . '://' . $p['host'] . (isset($p['port']) ? ':' . $p['port'] : '') . ($p['path'] ?? '/');
    return $base . '?' . http_build_query($q);
}

function has_sql_error(string $body): ?string {
    $low = strtolower($body);
    foreach (ERROR_SIGNATURES as $sig) if (str_contains($low, $sig)) return $sig;
    return null;
}

function scan(string $url, string $cookie = ''): array {
    $findings = [];
    parse_str(parse_url($url, PHP_URL_QUERY) ?? '', $params);
    if (!$params) return ['params' => 0, 'findings' => []];
    [$baseBody, $baseTime] = fetch($url, $cookie);
    foreach ($params as $name => $orig) {
        foreach (["'", '"', "\\"] as $payload) {
            [$b] = fetch(with_param($url, $name, $orig . $payload), $cookie);
            if ($sig = has_sql_error($b)) { $findings[] = [$name, 'Error-based', "Payload {$payload} caused a SQL error message ({$sig})."]; break; }
        }
        foreach ([["' AND '1'='1", "' AND '1'='2"], [" AND 1=1", " AND 1=2"]] as [$t, $f]) {
            [$bt] = fetch(with_param($url, $name, $orig . $t), $cookie);
            [$bf] = fetch(with_param($url, $name, $orig . $f), $cookie);
            if (strlen($bt) === strlen($baseBody) && strlen($bf) !== strlen($baseBody)) {
                $findings[] = [$name, 'Boolean-based', "True condition matched the normal page; false condition changed it (" . trim($t) . " / " . trim($f) . ")."]; break;
            }
        }
        [, $t] = fetch(with_param($url, $name, $orig . "' AND SLEEP(3)-- -"), $cookie);
        if ($t >= 3 && $baseTime < 2) $findings[] = [$name, 'Time-based', "Response was delayed " . round($t, 1) . "s after SLEEP(3)."];
    }
    return ['params' => count($params), 'findings' => $findings];
}

function risk_score(array $findings): int {
    $s = 0; foreach ($findings as $f) $s += WEIGHT[SEVERITY[$f[1]]];
    return min(100, $s);
}

// ---- CSV export of a scan (latest, or ?scan=<id> from history) ----
if (isset($_GET['export'])) {
    $l = $_SESSION['last'] ?? null;
    if (!empty($_GET['scan'])) {
        foreach ($_SESSION['history'] ?? [] as $e) { if (($e['id'] ?? null) === $_GET['scan']) { $l = $e; break; } }
    }
    if (empty($l)) { header('Location: index.php'); exit; }
    header('Content-Type: text/csv'); header('Content-Disposition: attachment; filename="sqli-scan-report.csv"');
    $o = fopen('php://output', 'w');
    fputcsv($o, ['Target', 'Time', 'Parameter', 'Technique', 'Severity', 'Evidence']);
    foreach ($l['findings'] as [$p, $t, $d]) fputcsv($o, [$l['url'], $l['date'], $p, $t, SEVERITY[$t], $d]);
    if (!$l['findings']) fputcsv($o, [$l['url'], $l['date'], '-', '-', 'None', 'No indicators found']);
    exit;
}

// ---- Actions (post, then redirect) ----
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (($_POST['action'] ?? '') === 'clear') { $_SESSION['history'] = []; $_SESSION['last'] = null; }
    else {
        $url = trim($_POST['url'] ?? '');
        $cookie = trim($_POST['cookie'] ?? '');
        if (!filter_var($url, FILTER_VALIDATE_URL) || !in_array(parse_url($url, PHP_URL_SCHEME), ['http', 'https'])) {
            $_SESSION['error'] = 'Enter a full URL starting with http:// or https://';
        } elseif (!is_lab_target($url)) {
            $_SESSION['error'] = 'Blocked: only localhost and private-network addresses can be scanned.';
        } else {
            $GLOBALS['reqs'] = 0; $t0 = microtime(true);
            $r = scan($url, $cookie);
            $r += ['id' => bin2hex(random_bytes(5)), 'url' => $url, 'cookie' => $cookie, 'time' => date('H:i'), 'date' => date('Y-m-d H:i:s'),
                   'duration' => round(microtime(true) - $t0, 1), 'requests' => $GLOBALS['reqs'],
                   'vuln_params' => count(array_unique(array_column($r['findings'], 0))), 'score' => risk_score($r['findings'])];
            $_SESSION['last'] = $r;
            $_SESSION['history'] = array_slice(array_merge([$r], $_SESSION['history'] ?? []), 0, 15);
        }
    }
    header('Location: index.php'); exit;
}

$error = $_SESSION['error'] ?? null; unset($_SESSION['error']);
$history = $_SESSION['history'] ?? [];
// Give every entry a stable id, even older ones scanned before 'id' existed.
foreach ($history as $idx => &$e) { if (empty($e['id'])) $e['id'] = 'row' . $idx; }
unset($e);
$_SESSION['history'] = $history;

$viewing = $_GET['scan'] ?? null;
$last = $_SESSION['last'] ?? null;
if ($viewing) {
    foreach ($history as $e) { if (($e['id'] ?? null) === $viewing) { $last = $e; break; } }
}

$typeCounts = array_fill_keys(array_keys(SEVERITY), 0); $totalFindings = 0; $vulnScans = 0; $totalReq = 0;
foreach ($history as $e) {
    foreach ($e['findings'] as $f) { $typeCounts[$f[1]]++; $totalFindings++; }
    if ($e['findings']) $vulnScans++;
    $totalReq += $e['requests'] ?? 0;
}

$score = $last['score'] ?? 0;
[$riskLabel, $riskColor] = $score >= 70 ? ['Critical risk', '#FF5A5A'] : ($score >= 30 ? ['Elevated risk', '#F5A524'] : ['Low risk', '#2EE57A']);
$circ = 2 * M_PI * 54;

// trend chart points (oldest -> newest)
$series = array_reverse(array_map(fn($e) => count($e['findings']), $history));
$W = 360; $H = 120; $pts = [];
if (count($series) >= 2) {
    $mx = max(1, max($series));
    foreach ($series as $i => $v) $pts[] = [round($i * $W / (count($series) - 1), 1), round($H - 10 - ($v / $mx) * ($H - 30), 1)];
}
$line = implode(' ', array_map(fn($p) => $p[0] . ',' . $p[1], $pts));
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SQLi Scanner</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root{color-scheme:dark;--navy:#050806;--navy2:#0F1A13;--canvas:#070A08;--card:#0E1410;--line:#1E2B22;--text:#E6F2EA;--muted:#8AA394;
--teal:#16A34A;--teal2:#2EE57A;--soft:#102319;--font:'Inter',system-ui,-apple-system,'Segoe UI',sans-serif;--mono:ui-monospace,Consolas,monospace;
--shadow:0 1px 2px rgba(0,0,0,.5),0 8px 24px rgba(0,0,0,.35)}
*{box-sizing:border-box;margin:0}
body{font-family:var(--font);background:radial-gradient(900px 420px at 85% -8%,rgba(46,229,122,.09),transparent),var(--canvas);color:var(--text);display:grid;grid-template-columns:250px 1fr;min-height:100vh;font-size:14px}
a{color:inherit;text-decoration:none}
:focus-visible{outline:3px solid var(--teal2);outline-offset:2px}
.ic{width:18px;height:18px;flex:none}

aside{background:linear-gradient(180deg,#050806,#000);border-right:1px solid var(--line);color:#9DB8A8;padding:26px 16px;position:sticky;top:0;height:100vh;display:flex;flex-direction:column;gap:26px}
.brand{display:flex;align-items:center;gap:12px;color:#fff;padding:0 8px}
.logo{width:42px;height:42px;border-radius:13px;background:radial-gradient(circle at 30% 25%,#14301F,#07110B);border:1px solid #1F3B2A;display:grid;place-items:center;flex:none;box-shadow:0 0 18px rgba(46,229,122,.22),inset 0 0 10px rgba(46,229,122,.08)}
.brand .name{font-size:19px;font-weight:700;letter-spacing:-.02em}

.menu-label{font-size:11.5px;color:#5F7D6C;padding:0 12px;margin-bottom:8px;font-weight:600}
nav{display:flex;flex-direction:column;gap:3px}
nav a{display:flex;gap:12px;align-items:center;padding:11px 12px;border-radius:10px;font-weight:500}
nav a.on{background:var(--navy2);color:#fff;box-shadow:inset 3px 0 0 var(--teal2);color:var(--teal2)}
nav a:hover{background:var(--navy2);color:#fff}
.guard{margin-top:auto;background:var(--navy2);border-radius:14px;padding:16px;font-size:12.5px;line-height:1.55}
.guard .ic{color:var(--teal2);margin-bottom:8px;width:22px;height:22px}.guard b{color:#fff;display:block;margin-bottom:4px}

.wrap{min-width:0}
.top{display:flex;justify-content:space-between;align-items:center;padding:16px 36px;background:rgba(14,20,16,.9);backdrop-filter:blur(8px);border-bottom:1px solid var(--line);position:sticky;top:0;z-index:5}
.crumb{color:var(--muted);font-size:13px}.crumb b{color:var(--text);font-weight:600}
.top-r{display:flex;align-items:center;gap:14px}
.pill{background:var(--soft);color:var(--teal2);border:1px solid #1B3A27;font-weight:600;font-size:12px;padding:5px 12px;border-radius:99px;display:flex;align-items:center;gap:7px}
.pill:before{content:"";width:7px;height:7px;border-radius:50%;background:#2EE57A;box-shadow:0 0 8px #2EE57A}
.avatar{width:34px;height:34px;border-radius:50%;background:linear-gradient(135deg,var(--teal),var(--teal2));color:#03120A;display:grid;place-items:center;font-weight:700;font-size:13px;border:0;cursor:pointer;font-family:inherit}
.profile{position:relative}
.profile-menu{position:absolute;right:0;top:calc(100% + 10px);width:240px;background:var(--card);border:1px solid var(--line);
  border-radius:14px;box-shadow:var(--shadow);padding:16px;display:none;z-index:20}
.profile-menu.open{display:block}
.pm-head{display:flex;gap:10px;align-items:center;padding-bottom:14px;border-bottom:1px solid var(--line)}
.pm-name{font-weight:700;font-size:14px}
.pm-email{color:var(--muted);font-size:12px;margin-top:2px;word-break:break-all}
.pm-row{display:flex;justify-content:space-between;font-size:12.5px;color:var(--muted);padding:12px 0;border-bottom:1px solid var(--line)}
.pm-row b{color:var(--text);font-weight:600}
.pm-logout{display:flex;align-items:center;gap:8px;margin-top:12px;color:#FF8A8A;font-size:13.5px;font-weight:600}
.pm-logout:hover{color:#FFADAD}
.pm-logout .ic{width:16px;height:16px}

main{padding:28px 36px 56px;display:flex;flex-direction:column;gap:22px}
h1{font-size:24px;font-weight:700;letter-spacing:-.02em}.lead{color:var(--muted);margin-top:5px;font-size:14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:16px;box-shadow:var(--shadow);padding:22px}
.card-h{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;gap:12px}
.card-h h2{font-size:15px;font-weight:600}.card-h span{color:var(--muted);font-size:12.5px}

.scan{display:flex;gap:12px;flex-wrap:wrap}
.field{flex:1;min-width:260px;display:flex;align-items:center;gap:10px;border:1.5px solid var(--line);border-radius:12px;padding:0 14px;background:#0A100C;color:var(--muted)}
.field:focus-within{border-color:var(--teal2);box-shadow:0 0 0 4px var(--soft)}
.field input{flex:1;border:0;outline:0;padding:14px 0;font-family:var(--mono);font-size:13.5px;background:transparent;color:var(--text)}
button,.btn{font:inherit;font-weight:600;cursor:pointer;border:0;border-radius:12px;padding:0 26px;min-height:48px;background:linear-gradient(135deg,var(--teal),var(--teal2));color:#03120A;display:inline-flex;align-items:center;gap:8px;box-shadow:0 4px 16px rgba(46,229,122,.25)}
button:hover,.btn:hover{filter:brightness(.95)}
.btn.out,button.out{background:transparent;color:var(--text);border:1px solid var(--line);box-shadow:none;min-height:36px;padding:0 14px;font-size:13px}
.alert{background:#2A1213;border:1px solid #5A2023;color:#FF9A9A;border-radius:10px;padding:11px 14px;margin-top:14px;font-size:13.5px}
.checks{display:flex;gap:18px;flex-wrap:wrap;margin-top:14px;color:var(--muted);font-size:12.5px}
.checks span:before{content:"✓ ";color:#2EE57A;font-weight:700}

.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:16px}
.kpi{display:flex;gap:14px;align-items:center}
.kpi .ico{width:44px;height:44px;border-radius:12px;display:grid;place-items:center;flex:none}
.kpi .n{font-size:26px;font-weight:700;letter-spacing:-.02em;line-height:1.1}.kpi .l{color:var(--muted);font-size:12.5px;margin-top:3px}
.c-teal{background:var(--soft);color:var(--teal2)}.c-red{background:#2A1213;color:#FF6B6B}.c-vio{background:#13261B;color:#7CF0A6}.c-amb{background:#2A2310;color:#F5C84B}

.cols{display:grid;grid-template-columns:1.9fr 1fr;gap:18px;align-items:start}.stack{display:flex;flex-direction:column;gap:18px}
.sum{display:flex;gap:24px;align-items:center;flex-wrap:wrap;padding-bottom:20px;border-bottom:1px solid var(--line);margin-bottom:6px}
.gauge{position:relative;width:128px;height:128px;flex:none}.gauge svg{transform:rotate(-90deg)}
.gauge .mid{position:absolute;inset:0;display:grid;place-content:center;text-align:center}
.gauge .mid b{font-size:30px;font-weight:700;line-height:1}.gauge .mid span{font-size:11px;color:var(--muted);margin-top:3px}
.ring{stroke-dasharray:<?= $circ ?>;stroke-dashoffset:<?= $circ ?>;animation:fill 1s .1s ease-out forwards}
@keyframes fill{to{stroke-dashoffset:<?= $circ * (1 - $score / 100) ?>}}
.verdict{font-size:19px;font-weight:700;letter-spacing:-.01em}
.url{font-family:var(--mono);font-size:12.5px;color:var(--muted);word-break:break-all;margin:6px 0 14px}
.meta{display:flex;gap:22px;flex-wrap:wrap}.meta div{font-size:12px;color:var(--muted)}.meta b{display:block;font-size:15px;color:var(--text);font-weight:600;margin-top:2px}

table{width:100%;border-collapse:collapse}
th{text-align:left;font-weight:600;color:var(--muted);font-size:12px;padding:10px 12px;background:#0A100C;border-bottom:1px solid var(--line)}
th:first-child{border-radius:8px 0 0 8px}th:last-child{border-radius:0 8px 8px 0}
td{padding:14px 12px;border-bottom:1px solid var(--line);vertical-align:top;line-height:1.5}tr:last-child td{border-bottom:0}
code{font-family:var(--mono);font-size:12.5px;color:var(--teal2);background:#0A100C;border:1px solid var(--line);padding:2px 7px;border-radius:6px}
.badge{display:inline-flex;align-items:center;gap:6px;padding:3px 10px;border-radius:99px;font-size:12px;font-weight:600}
.badge:before{content:"";width:6px;height:6px;border-radius:50%;background:currentColor}
.s-Critical{background:#3A1416;color:#FF7A7A}.s-High{background:#3A2412;color:#FFA25C}.s-ok{background:#0F2D1B;color:#4ADE80}.s-warn{background:#33290E;color:#F5C84B}
.empty{color:var(--muted);line-height:1.65;padding:10px 0}
.fix{margin-top:18px;background:#0B1A11;border:1px solid #1F3B2A;border-radius:12px;padding:16px 18px}
.fix b{display:block;margin-bottom:8px;color:var(--teal2)}.fix ul{padding-left:18px;color:#BFD3C6;line-height:1.75}

.legend{display:flex;flex-direction:column;gap:12px;flex:1}.legend div{display:flex;justify-content:space-between;align-items:center;font-size:13px}
.legend i{display:inline-block;width:10px;height:10px;border-radius:3px;margin-right:9px}
.donut{display:flex;align-items:center;gap:20px}
.trunc{max-width:420px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:block;font-family:var(--mono);font-size:12.5px}
.row-link{cursor:pointer}.row-link:hover td{background:#0E1813}.row-sel td{background:var(--soft)}

@media (max-width:1000px){.cols{grid-template-columns:1fr}.kpis{grid-template-columns:repeat(2,1fr)}}
@media (max-width:860px){body{grid-template-columns:1fr}aside{position:static;height:auto;flex-direction:row;flex-wrap:wrap;align-items:center;padding:14px 18px;gap:12px}
nav{flex-direction:row}.guard,.menu-label{display:none}.top{padding:14px 18px}main{padding:20px 16px 40px}}
@media (prefers-reduced-motion:reduce){.ring{animation:none;stroke-dashoffset:<?= $circ * (1 - $score / 100) ?>}}
</style>
</head>
<body>
<aside>
  <div class="brand">
    <span class="logo" aria-hidden="true">
      <svg viewBox="0 0 40 40" width="26" height="26" fill="none" stroke="url(#lg)" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
        <defs><linearGradient id="lg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#7CF0A6"/><stop offset="1" stop-color="#16A34A"/></linearGradient></defs>
        <path d="M20 4.5l12 4.2v9.6c0 7.4-5 12.4-12 15.2-7-2.8-12-7.8-12-15.2V8.7l12-4.2z"/>
        <circle cx="19" cy="17.5" r="5"/>
        <path d="M22.8 21.3l4.2 4.2"/>
        <path d="M16.5 17.5h5" stroke-width="1.6"/>
      </svg>
    </span>
    <b class="name">SQLi Scanner</b>
  </div>
  <div>
    <div class="menu-label">Workspace</div>
    <nav>
      <a class="on" href="#top"><?= icon('grid') ?>Dashboard</a>
      <a href="index.php?new=1#scan"><?= icon('scan') ?>New scan</a>
      <a href="#latest"><?= icon('layers') ?>Latest report</a>
      <a href="history.php"><?= icon('clock') ?>Scan history</a>
    </nav>
  </div>
  <div class="guard"><?= icon('shield') ?><b>Authorised targets only</b></div>
</aside>

<div class="wrap" id="top">
  <header class="top">
    <div class="crumb">Security / <b>Dashboard</b></div>
    <div class="top-r"><span class="pill">Admin</span>
      <div class="profile">
        <button class="avatar" type="button" onclick="document.getElementById('profileMenu').classList.toggle('open')" aria-haspopup="true" aria-label="Account menu">
          <?= h(strtoupper(substr(current_user(), 0, 2))) ?>
        </button>
        <div class="profile-menu" id="profileMenu">
          <?php $acc = current_account(); ?>
          <div class="pm-head">
            <div class="avatar" style="width:38px;height:38px;font-size:14px"><?= h(strtoupper(substr($acc['username'], 0, 2))) ?></div>
            <div><div class="pm-name"><?= h($acc['username']) ?></div><div class="pm-email"><?= h($acc['email'] ?? '-') ?></div></div>
          </div>
          <div class="pm-row"><span>Registered</span><b><?= h($acc['created'] ?? '-') ?></b></div>
          <a class="pm-logout" href="logout.php"><?= icon('send') ?>Log out</a>
        </div>
      </div>
    </div>
  </header>

  <main>
    <div>
      <h1>SQL injection assessment</h1>
      <p class="lead">Test a lab page for injectable parameters and review findings with remediation guidance.</p>
    </div>

    <section class="card" id="scan">
      <div class="card-h"><h2>New scan</h2><span>GET parameters</span></div>
      <form method="post" class="scan">
        <?php $prefillUrl = isset($_GET['new']) ? '' : ($last['url'] ?? ''); $prefillCookie = isset($_GET['new']) ? '' : ($last['cookie'] ?? ''); ?>
        <label class="field" style="flex:2"><?= icon('scan') ?><input type="text" name="url" placeholder="Enter the url here" aria-label="Target URL" value="<?= h($prefillUrl) ?>" required></label>
        <label class="field"><?= icon('shield') ?><input type="text" name="cookie" placeholder="Enter the cookies here" aria-label="Cookie header" value="<?= h($prefillCookie) ?>"></label>
        <button type="submit"><?= icon('send') ?>Start scan</button>
      </form>
      <?php if ($error): ?><div class="alert" role="alert"><?= h($error) ?></div><?php endif; ?>
      <div class="checks"><span>Error-based</span><span>Boolean-based</span><span>Time-based</span></div>
    </section>

    <section class="kpis">
      <div class="card kpi"><div class="ico c-teal"><?= icon('scan') ?></div><div><div class="n"><?= count($history) ?></div><div class="l">Scans completed</div></div></div>
      <div class="card kpi"><div class="ico c-red"><?= icon('shield') ?></div><div><div class="n"><?= $vulnScans ?></div><div class="l">Vulnerable targets</div></div></div>
      <div class="card kpi"><div class="ico c-vio"><?= icon('bug') ?></div><div><div class="n"><?= $totalFindings ?></div><div class="l">Total findings</div></div></div>
      <div class="card kpi"><div class="ico c-amb"><?= icon('send') ?></div><div><div class="n"><?= $totalReq ?></div><div class="l">Test requests sent</div></div></div>
    </section>

    <section class="cols">
      <div class="card" id="latest">
        <div class="card-h"><h2><?= ($viewing && $last) ? 'Scan report' : 'Latest report' ?></h2>
          <div style="display:flex;gap:10px">
          <?php if ($viewing): ?><a class="btn out" href="index.php#latest">&larr; Back to latest</a><?php endif; ?>
          <?php if ($last): ?><a class="btn out" href="?export=1<?= $viewing ? '&scan='.h($viewing) : '' ?>"><?= icon('down') ?>Export CSV</a><?php endif; ?>
          </div></div>
        <?php if (!$last): ?>
          <p class="empty">No scans yet. Enter a lab URL such as <code>http://localhost/sqli_lab/vuln.php?id=1</code> and select Start scan.</p>
        <?php else: $noParams = $last['params'] === 0; $n = count($last['findings']); ?>
          <div class="sum">
            <div class="gauge" role="img" aria-label="Risk score <?= $score ?> out of 100">
              <svg width="128" height="128" viewBox="0 0 128 128">
                <circle cx="64" cy="64" r="54" fill="none" stroke="#1A251E" stroke-width="11"/>
                <circle class="ring" cx="64" cy="64" r="54" fill="none" stroke="<?= $riskColor ?>" stroke-width="11" stroke-linecap="round"/>
              </svg>
              <div class="mid"><b style="color:<?= $riskColor ?>"><?= $score ?></b><span>risk score</span></div>
            </div>
            <div style="flex:1;min-width:220px">
              <div class="verdict"><?= $noParams ? 'No parameters to test' : $riskLabel ?></div>
              <div class="url"><?= h($last['url']) ?></div>
              <div class="meta">
                <div>Findings<b><?= $n ?></b></div>
                <div>Parameters<b><?= $last['vuln_params'] ?> of <?= $last['params'] ?> vulnerable</b></div>
                <div>Requests<b><?= $last['requests'] ?? 0 ?></b></div>
                <div>Duration<b><?= $last['duration'] ?? 0 ?>s</b></div>
              </div>
            </div>
          </div>
          <?php if ($noParams): ?>
            <p class="empty">This URL has no query parameters. Add one, such as <code>?id=1</code>, and scan again.</p>
          <?php elseif (!$n): ?>
            <p class="empty">The basic checks found no injection indicators. This is not proof the page is safe, because only a small set of payloads was tested.</p>
          <?php else: ?>
            <table>
              <tr><th>Parameter</th><th>Technique</th><th>Severity</th><th>Evidence</th></tr>
              <?php foreach ($last['findings'] as [$p, $type, $detail]): $sv = SEVERITY[$type]; ?>
                <tr><td><code><?= h($p) ?></code></td><td><?= h($type) ?><br><small style="color:var(--muted)">CWE-89</small></td>
                <td><span class="badge s-<?= $sv ?>"><?= $sv ?></span></td><td><?= h($detail) ?></td></tr>
              <?php endforeach; ?>
            </table>
            <div class="fix"><b>Recommended fixes</b>
              <ul>
                <li>Use prepared statements (PDO or mysqli) so input is never joined into SQL text.</li>
                <li>Validate each parameter's type and length on the server.</li>
                <li>Hide database error messages from users and log them privately.</li>
                <li>Connect with a least-privilege database account, not <code>root</code>.</li>
              </ul>
            </div>
          <?php endif; ?>
        <?php endif; ?>
      </div>

      <div class="stack">
        <div class="card">
          <div class="card-h"><h2>Findings per scan</h2><span>Recent</span></div>
          <?php if (count($pts) < 2): ?><p class="empty">Run at least two scans to see a trend.</p>
          <?php else: ?>
            <svg viewBox="0 0 <?= $W ?> <?= $H ?>" width="100%" role="img" aria-label="Findings per scan trend">
              <defs><linearGradient id="g" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#2EE57A" stop-opacity=".28"/><stop offset="1" stop-color="#2EE57A" stop-opacity="0"/></linearGradient></defs>
              <polygon points="0,<?= $H ?> <?= $line ?> <?= $W ?>,<?= $H ?>" fill="url(#g)"/>
              <polyline points="<?= $line ?>" fill="none" stroke="#2EE57A" stroke-width="2.5" stroke-linejoin="round"/>
              <?php foreach ($pts as $p): ?><circle cx="<?= $p[0] ?>" cy="<?= $p[1] ?>" r="3.5" fill="#0E1410" stroke="#2EE57A" stroke-width="2"/><?php endforeach; ?>
            </svg>
          <?php endif; ?>
        </div>

        <div class="card">
          <div class="card-h"><h2>By technique</h2><span><?= $totalFindings ?> total</span></div>
          <div class="donut">
            <svg width="110" height="110" viewBox="0 0 110 110" style="transform:rotate(-90deg);flex:none" role="img" aria-label="Findings by technique">
              <circle cx="55" cy="55" r="40" fill="none" stroke="#1A251E" stroke-width="14"/>
              <?php $c = 2 * M_PI * 40; $off = 0;
              if ($totalFindings) foreach ($typeCounts as $t => $v): if (!$v) continue; $len = $v / $totalFindings * $c; ?>
                <circle cx="55" cy="55" r="40" fill="none" stroke="<?= TYPE_COLOR[$t] ?>" stroke-width="14" stroke-dasharray="<?= round($len, 2) ?> <?= round($c - $len, 2) ?>" stroke-dashoffset="<?= round(-$off, 2) ?>"/>
              <?php $off += $len; endforeach; ?>
            </svg>
            <div class="legend">
              <?php foreach ($typeCounts as $t => $v): ?><div><span><i style="background:<?= TYPE_COLOR[$t] ?>"></i><?= h($t) ?></span><b><?= $v ?></b></div><?php endforeach; ?>
            </div>
          </div>
        </div>
      </div>
    </section>

    <section class="card" id="history">
      <div class="card-h"><h2>Scan history</h2>
        <?php if ($history): ?><form method="post"><input type="hidden" name="action" value="clear"><button class="out" type="submit">Clear history</button></form><?php endif; ?></div>
      <?php if (!$history): ?><p class="empty">Completed scans appear here for this browser session.</p>
      <?php else: ?>
        <table>
          <tr><th>Time</th><th>Target</th><th>Parameters</th><th>Risk score</th><th>Result</th></tr>
          <?php foreach ($history as $e): $n = count($e['findings']); $sel = ($viewing === ($e['id'] ?? null)); ?>
            <tr class="row-link<?= $sel ? ' row-sel' : '' ?>" onclick="location.href='?scan=<?= h($e['id'] ?? '') ?>#latest'">
              <td><?= h($e['time']) ?></td>
              <td><span class="trunc" title="<?= h($e['url']) ?>"><?= h($e['url']) ?></span></td>
              <td><?= $e['params'] ?></td><td><?= $e['score'] ?? 0 ?>/100</td>
              <td><?php if ($e['params'] === 0): ?><span class="badge s-warn">No parameters</span>
                  <?php elseif ($n): ?><span class="badge s-High"><?= $n ?> finding<?= $n > 1 ? 's' : '' ?></span>
                  <?php else: ?><span class="badge s-ok">Clean</span><?php endif; ?></td>
            </tr>
          <?php endforeach; ?>
        </table>
      <?php endif; ?>
    </section>
  </main>
</div>
<script>
document.addEventListener('click', function (e) {
  var menu = document.getElementById('profileMenu');
  if (!menu) return;
  var profile = menu.closest('.profile');
  if (profile && !profile.contains(e.target)) menu.classList.remove('open');
});
</script>
</body>
</html>
