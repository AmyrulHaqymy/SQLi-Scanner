<?php
// INTENTIONALLY VULNERABLE test target. Local lab use only - never deploy.
// The query below is still built with raw string concatenation on purpose,
// so the scanner has something real to find. Only the page's look changed.
mysqli_report(MYSQLI_REPORT_OFF);
$db = mysqli_connect("localhost", "root", "", "sqli_lab");
$id = $_GET['id'] ?? '1';
$sql = "SELECT username, email FROM users WHERE id = '$id'";   // vulnerable concatenation
$res = mysqli_query($db, $sql);

$rows = []; $dbError = null;
if (!$res) {
    $dbError = mysqli_error($db);
} else {
    while ($row = mysqli_fetch_assoc($res)) $rows[] = $row;
}

function initials(string $name): string {
    $name = trim($name);
    return $name === '' ? '?' : strtoupper(substr($name, 0, 1));
}
function h($s): string { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Staff Directory - User lookup</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght@9..144,500;9..144,600&family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root{color-scheme:dark;
  --paper:#070A08; --card:#0E1410; --ink:#E6F2EA; --muted:#7FA08E; --line:#1E2B22;
  --moss:#2EE57A; --moss-soft:#102319; --clay:#FF6B5A;
  --serif:'Fraunces',Georgia,serif; --sans:'Inter',system-ui,-apple-system,sans-serif;
}
*{box-sizing:border-box;margin:0}
body{font-family:var(--sans);background:radial-gradient(800px 360px at 80% -10%,rgba(46,229,122,.08),transparent),var(--paper);color:var(--ink);min-height:100vh;
  padding:64px 24px;display:flex;flex-direction:column;align-items:center;gap:40px}
.wrap{width:100%;max-width:560px}
.kicker{font-size:13px;color:var(--moss);font-weight:600;letter-spacing:.02em;margin-bottom:10px}
h1{font-family:var(--serif);font-size:38px;font-weight:600;letter-spacing:-.01em;line-height:1.08;color:var(--ink)}
.lead{color:var(--muted);margin-top:10px;font-size:15px;line-height:1.55;max-width:46ch}
.id-tag{display:inline-flex;align-items:center;gap:7px;margin-top:18px;background:var(--moss-soft);color:var(--moss);
  font-size:12.5px;font-weight:600;padding:6px 13px;border-radius:99px;border:1px solid #1F3B2A}
.id-tag b{font-family:ui-monospace,Consolas,monospace;font-weight:600}

.results{margin-top:30px;display:flex;flex-direction:column;gap:12px}
.person{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:18px 20px;
  display:flex;align-items:center;gap:16px;box-shadow:0 1px 2px rgba(0,0,0,.4)}
.avatar{width:46px;height:46px;border-radius:12px;background:linear-gradient(135deg,#16A34A,var(--moss));color:#03120A;font-family:var(--serif);
  font-size:18px;display:grid;place-items:center;flex:none}
.person .name{font-weight:600;font-size:15.5px}
.person .mail{color:var(--muted);font-size:13.5px;margin-top:2px;font-family:ui-monospace,Consolas,monospace}

.empty,.err{margin-top:30px;border-radius:16px;padding:22px;font-size:14px;line-height:1.6}
.empty{background:var(--card);border:1px dashed var(--line);color:var(--muted)}
.err{background:#2A1313;border:1px solid #5A2023;color:#FFB4A8}
.err b{display:block;color:var(--clay);font-size:13px;letter-spacing:.02em;margin-bottom:6px;font-weight:600}
.err code{display:block;margin-top:8px;font-family:ui-monospace,Consolas,monospace;font-size:12.5px;
  background:rgba(0,0,0,.35);color:#FF8C7A;padding:10px 12px;border-radius:8px;word-break:break-word}

footer{color:var(--muted);font-size:12px;text-align:center}
footer a{color:var(--moss)}
.mail{color:var(--muted)!important}
@media (max-width:480px){h1{font-size:30px}body{padding:40px 16px}}
</style>
</head>
<body>
<div class="wrap">
  <div class="kicker">Internal tool</div>
  <h1>Staff directory lookup</h1>
  <p class="lead">Enter a staff ID in the URL's <code>id</code> parameter to find their name and contact email.</p>
  <div class="id-tag">Looking up ID <b><?= h($id) ?></b></div>

  <div class="results">
    <?php if ($dbError): ?>
      <div class="err">
        <b>Database error</b>
        That ID could not be looked up right now.
        <code><?= h($dbError) ?></code>
      </div>
    <?php elseif (!$rows): ?>
      <div class="empty">No staff member matches that ID.</div>
    <?php else: foreach ($rows as $row): ?>
      <div class="person">
        <div class="avatar"><?= h(initials($row['username'] ?? '')) ?></div>
        <div>
          <div class="name"><?= h($row['username']) ?></div>
          <div class="mail"><?= h($row['email']) ?></div>
        </div>
      </div>
    <?php endforeach; endif; ?>
  </div>
</div>
<footer>Lab target for <a href="index.php">SQLi Scanner</a> - local use only.</footer>
</body>
</html>