<?php
// Standalone report view for one scan from history - does not touch the dashboard's "latest" state.
require_once __DIR__ . '/auth.php';
require_login();

const SEVERITY = ['Boolean-based' => 'Critical', 'Error-based' => 'High', 'Time-based' => 'High'];
const TYPE_COLOR = ['Error-based' => '#FF5A5A', 'Boolean-based' => '#2EE57A', 'Time-based' => '#F5C84B'];

function icon(string $n): string {
    $p = [
        'grid'  => '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
        'scan'  => '<circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/>',
        'clock' => '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
        'shield'=> '<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6l8-3z"/>',
        'layers'=> '<path d="M12 3l9 5-9 5-9-5 9-5zM3 13l9 5 9-5"/>',
        'down'  => '<path d="M12 4v11m0 0l-4-4m4 4l4-4M5 20h14"/>',
    ];
    return '<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">' . ($p[$n] ?? '') . '</svg>';
}

$history = $_SESSION['history'] ?? [];
foreach ($history as $idx => &$e) { if (empty($e['id'])) $e['id'] = 'row' . $idx; }
unset($e);
$_SESSION['history'] = $history;

$scanId = $_GET['scan'] ?? null;
$r = null;
foreach ($history as $e) { if (($e['id'] ?? null) === $scanId) { $r = $e; break; } }

if (isset($_GET['export']) && $r) {
    header('Content-Type: text/csv'); header('Content-Disposition: attachment; filename="sqli-scan-report.csv"');
    $o = fopen('php://output', 'w');
    fputcsv($o, ['Target', 'Time', 'Parameter', 'Technique', 'Severity', 'Evidence']);
    foreach ($r['findings'] as [$p, $t, $d]) fputcsv($o, [$r['url'], $r['date'], $p, $t, SEVERITY[$t], $d]);
    if (!$r['findings']) fputcsv($o, [$r['url'], $r['date'], '-', '-', 'None', 'No indicators found']);
    exit;
}

$acc = current_account();
$score = $r['score'] ?? 0;
[$riskLabel, $riskColor] = $score >= 70 ? ['Critical risk', '#FF5A5A'] : ($score >= 30 ? ['Elevated risk', '#F5A524'] : ['Low risk', '#2EE57A']);
$circ = 2 * M_PI * 54;

$typeCounts = array_fill_keys(array_keys(SEVERITY), 0);
if ($r) foreach ($r['findings'] as $f) $typeCounts[$f[1]]++;
$totalFindings = array_sum($typeCounts);
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Scan report - SQLi Scanner</title>
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
nav a.on{background:var(--navy2);color:var(--teal2);box-shadow:inset 3px 0 0 var(--teal2)}
nav a:hover{background:var(--navy2);color:#fff}
.guard{margin-top:auto;background:var(--navy2);border-radius:14px;padding:16px;font-size:12.5px;line-height:1.55}
.guard .ic{color:var(--teal2);margin-bottom:8px;width:22px;height:22px}.guard b{color:#fff;display:block;margin-bottom:4px}

.wrap{min-width:0}
.top{display:flex;justify-content:space-between;align-items:center;padding:16px 36px;background:rgba(14,20,16,.9);backdrop-filter:blur(8px);border-bottom:1px solid var(--line);position:sticky;top:0;z-index:5}
.crumb{color:var(--muted);font-size:13px}.crumb b{color:var(--text);font-weight:600}
.top-r{display:flex;align-items:center;gap:14px}
.pill{background:var(--soft);color:var(--teal2);border:1px solid #1B3A27;font-weight:600;font-size:12px;padding:5px 12px;border-radius:99px;display:flex;align-items:center;gap:7px}
.pill:before{content:"";width:7px;height:7px;border-radius:50%;background:#2EE57A;box-shadow:0 0 8px #2EE57A}
.avatar{width:34px;height:34px;border-radius:50%;background:linear-gradient(135deg,var(--teal),var(--teal2));color:#03120A;display:grid;place-items:center;font-weight:700;font-size:13px;border:0}

main{padding:28px 36px 56px;display:flex;flex-direction:column;gap:22px}
h1{font-size:24px;font-weight:700;letter-spacing:-.02em}.lead{color:var(--muted);margin-top:5px;font-size:14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:16px;box-shadow:var(--shadow);padding:22px}
.card-h{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;gap:12px}
.card-h h2{font-size:15px;font-weight:600}
.btn,.out{font:inherit;font-weight:600;cursor:pointer;border:0;border-radius:12px;padding:0 14px;min-height:36px;font-size:13px;display:inline-flex;align-items:center;gap:8px;background:transparent;color:var(--text);border:1px solid var(--line)}
.btn:hover{background:var(--navy2)}

.cols{display:grid;grid-template-columns:1.9fr 1fr;gap:18px;align-items:start}
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
.s-Critical{background:#3A1416;color:#FF7A7A}.s-High{background:#3A2412;color:#FFA25C}
.empty{color:var(--muted);line-height:1.65;padding:10px 0}
.fix{margin-top:18px;background:#0B1A11;border:1px solid #1F3B2A;border-radius:12px;padding:16px 18px}
.fix b{display:block;margin-bottom:8px;color:var(--teal2)}.fix ul{padding-left:18px;color:#BFD3C6;line-height:1.75}
.legend{display:flex;flex-direction:column;gap:12px;flex:1}.legend div{display:flex;justify-content:space-between;align-items:center;font-size:13px}
.legend i{display:inline-block;width:10px;height:10px;border-radius:3px;margin-right:9px}
.donut{display:flex;align-items:center;gap:20px}

@media (max-width:1000px){.cols{grid-template-columns:1fr}}
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
        <circle cx="19" cy="17.5" r="5"/><path d="M22.8 21.3l4.2 4.2"/><path d="M16.5 17.5h5" stroke-width="1.6"/>
      </svg>
    </span>
    <b class="name">SQLi Scanner</b>
  </div>
  <div>
    <div class="menu-label">Workspace</div>
    <nav>
      <a href="index.php#top"><?= icon('grid') ?>Dashboard</a>
      <a href="index.php?new=1#scan"><?= icon('scan') ?>New scan</a>
      <a href="index.php#latest"><?= icon('layers') ?>Latest report</a>
      <a class="on" href="history.php"><?= icon('clock') ?>Scan history</a>
    </nav>
  </div>
  <div class="guard"><?= icon('shield') ?><b>Authorised targets only</b></div>
</aside>

<div class="wrap">
  <header class="top">
    <div class="crumb">Security / Scan history / <b>Report</b></div>
    <div class="top-r"><span class="pill">Admin</span>
      <div class="avatar" title="<?= h($acc['username'] ?? '') ?>" aria-hidden="true"><?= h(strtoupper(substr($acc['username'] ?? '?', 0, 2))) ?></div>
    </div>
  </header>

  <main>
    <div>
      <h1>Scan report</h1>
      <p class="lead"><a class="btn out" href="history.php" style="display:inline-flex">&larr; Back to scan history</a></p>
    </div>

    <?php if (!$r): ?>
      <section class="card"><p class="empty">This scan could not be found - it may have been cleared from history.</p></section>
    <?php else: $noParams = $r['params'] === 0; $n = count($r['findings']); ?>
      <section class="cols">
        <div class="card">
          <div class="card-h"><h2>Report</h2>
            <a class="btn" href="?scan=<?= h($r['id']) ?>&export=1"><?= icon('down') ?>Export CSV</a>
          </div>
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
              <div class="url"><?= h($r['url']) ?></div>
              <div class="meta">
                <div>Findings<b><?= $n ?></b></div>
                <div>Parameters<b><?= $r['vuln_params'] ?? 0 ?> of <?= $r['params'] ?> vulnerable</b></div>
                <div>Requests<b><?= $r['requests'] ?? 0 ?></b></div>
                <div>Duration<b><?= $r['duration'] ?? 0 ?>s</b></div>
                <div>Scanned<b><?= h($r['date'] ?? $r['time'] ?? '') ?></b></div>
              </div>
            </div>
          </div>
          <?php if ($noParams): ?>
            <p class="empty">This URL had no query parameters.</p>
          <?php elseif (!$n): ?>
            <p class="empty">The basic checks found no injection indicators for this scan.</p>
          <?php else: ?>
            <table>
              <tr><th>Parameter</th><th>Technique</th><th>Severity</th><th>Evidence</th></tr>
              <?php foreach ($r['findings'] as [$p, $type, $detail]): $sv = SEVERITY[$type]; ?>
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
        </div>

        <div class="card">
          <div class="card-h"><h2>By technique</h2><span style="color:var(--muted);font-size:12.5px"><?= $totalFindings ?> total</span></div>
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
      </section>
    <?php endif; ?>
  </main>
</div>
</body>
</html>