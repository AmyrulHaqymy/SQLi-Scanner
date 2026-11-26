<?php
// Full scan history page - lists every scan kept in this session.
require_once __DIR__ . '/auth.php';
require_login();

function h($s): string { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }

function icon(string $n): string {
    $p = [
        'grid'  => '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
        'scan'  => '<circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/>',
        'clock' => '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
        'shield'=> '<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6l8-3z"/>',
        'layers'=> '<path d="M12 3l9 5-9 5-9-5 9-5zM3 13l9 5 9-5"/>',
        'send'  => '<path d="M22 2L11 13M22 2l-7 20-4-9-9-4 20-7z"/>',
    ];
    return '<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">' . ($p[$n] ?? '') . '</svg>';
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'clear') {
    $_SESSION['history'] = []; $_SESSION['last'] = null;
    header('Location: history.php'); exit;
}

$history = $_SESSION['history'] ?? [];
foreach ($history as $idx => &$e) { if (empty($e['id'])) $e['id'] = 'row' . $idx; }
unset($e);
$_SESSION['history'] = $history;
$acc = current_account();
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Scan history - SQLi Scanner</title>
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
.avatar{width:34px;height:34px;border-radius:50%;background:linear-gradient(135deg,var(--teal),var(--teal2));color:#03120A;display:grid;place-items:center;font-weight:700;font-size:13px;border:0;cursor:pointer;font-family:inherit}

main{padding:28px 36px 56px;display:flex;flex-direction:column;gap:22px}
h1{font-size:24px;font-weight:700;letter-spacing:-.02em}.lead{color:var(--muted);margin-top:5px;font-size:14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:16px;box-shadow:var(--shadow);padding:22px}
.card-h{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;gap:12px}
.card-h h2{font-size:15px;font-weight:600}.card-h span{color:var(--muted);font-size:12.5px}
button,.btn{font:inherit;font-weight:600;cursor:pointer;border:0;border-radius:12px;padding:0 26px;min-height:48px;background:linear-gradient(135deg,var(--teal),var(--teal2));color:#03120A;display:inline-flex;align-items:center;gap:8px;box-shadow:0 4px 16px rgba(46,229,122,.25)}
.btn.out,button.out{background:transparent;color:var(--text);border:1px solid var(--line);box-shadow:none;min-height:36px;padding:0 14px;font-size:13px}

table{width:100%;border-collapse:collapse}
th{text-align:left;font-weight:600;color:var(--muted);font-size:12px;padding:10px 12px;background:#0A100C;border-bottom:1px solid var(--line)}
th:first-child{border-radius:8px 0 0 8px}th:last-child{border-radius:0 8px 8px 0}
td{padding:14px 12px;border-bottom:1px solid var(--line);vertical-align:top;line-height:1.5}tr:last-child td{border-bottom:0}
code{font-family:var(--mono);font-size:12.5px;color:var(--teal2);background:#0A100C;border:1px solid var(--line);padding:2px 7px;border-radius:6px}
.badge{display:inline-flex;align-items:center;gap:6px;padding:3px 10px;border-radius:99px;font-size:12px;font-weight:600}
.badge:before{content:"";width:6px;height:6px;border-radius:50%;background:currentColor}
.s-High{background:#3A2412;color:#FFA25C}.s-ok{background:#0F2D1B;color:#4ADE80}.s-warn{background:#33290E;color:#F5C84B}
.empty{color:var(--muted);line-height:1.65;padding:10px 0}
.trunc{max-width:460px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:block;font-family:var(--mono);font-size:12.5px}
.row-link{cursor:pointer}.row-link:hover td{background:#0E1813}

@media (max-width:860px){body{grid-template-columns:1fr}aside{position:static;height:auto;flex-direction:row;flex-wrap:wrap;align-items:center;padding:14px 18px;gap:12px}
nav{flex-direction:row}.guard,.menu-label{display:none}.top{padding:14px 18px}main{padding:20px 16px 40px}}
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
    <div class="crumb">Security / <b>Scan history</b></div>
    <div class="top-r"><span class="pill">Admin</span>
      <div class="avatar" title="<?= h($acc['username'] ?? '') ?>" aria-hidden="true"><?= h(strtoupper(substr($acc['username'] ?? '?', 0, 2))) ?></div>
    </div>
  </header>

  <main>
    <div>
      <h1>Scan history</h1>
      <p class="lead">Every scan run in this session. Click a row to open its full report.</p>
    </div>

    <section class="card">
      <div class="card-h"><h2><?= count($history) ?> scan<?= count($history) === 1 ? '' : 's' ?></h2>
        <?php if ($history): ?><form method="post"><input type="hidden" name="action" value="clear"><button class="out" type="submit">Clear history</button></form><?php endif; ?>
      </div>
      <?php if (!$history): ?>
        <p class="empty">No scans yet. Go to <a href="index.php#scan" style="color:var(--teal2);text-decoration:underline">New scan</a> to run one.</p>
      <?php else: ?>
        <table>
          <tr><th>Time</th><th>Target</th><th>Parameters</th><th>Risk score</th><th>Result</th></tr>
          <?php foreach ($history as $e): $n = count($e['findings']); ?>
            <tr class="row-link" onclick="location.href='report.php?scan=<?= h($e['id'] ?? '') ?>'">
              <td><?= h($e['date'] ?? $e['time']) ?></td>
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
</body>
</html>
