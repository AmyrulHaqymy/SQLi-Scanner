<?php
require_once __DIR__ . '/auth.php';

if (current_user()) { header('Location: index.php'); exit; }

$setup = !has_account();
$error = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $u = trim($_POST['username'] ?? '');
    $p = $_POST['password'] ?? '';
    if ($setup) {
        $email = trim($_POST['email'] ?? '');
        $p2 = $_POST['password2'] ?? '';
        if ($u === '' || $email === '' || $p === '') $error = 'Fill in a username, email and password.';
        elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) $error = 'Enter a valid email address.';
        elseif (strlen($p) < 6) $error = 'Password must be at least 6 characters.';
        elseif ($p !== $p2) $error = 'Passwords do not match.';
        else {
            auth_save($u, $email, $p);
            attempt_login($u, $p);
            header('Location: index.php'); exit;
        }
    } else {
        if (attempt_login($u, $p)) {
            $to = $_SESSION['redirect_after_login'] ?? 'index.php';
            unset($_SESSION['redirect_after_login']);
            header('Location: ' . $to); exit;
        } else {
            $error = 'Incorrect username or password.';
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><?= $setup ? 'Create admin account' : 'Sign in' ?> - SQLi Scanner</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root{color-scheme:dark;--navy:#050806;--card:#0E1410;--line:#1E2B22;--text:#E6F2EA;--muted:#8AA394;
--teal:#16A34A;--teal2:#2EE57A;--soft:#102319;--font:'Inter',system-ui,-apple-system,sans-serif}
*{box-sizing:border-box;margin:0}
html,body{height:100%}
body{font-family:var(--font);background:var(--navy);overflow-x:hidden;
color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;position:relative}
#globe{position:fixed;inset:0;width:100%;height:100%;display:block;z-index:0}
.box{width:100%;max-width:380px;position:relative;z-index:1}
.logo{width:48px;height:48px;border-radius:14px;background:radial-gradient(circle at 30% 25%,#14301F,#07110B);
border:1px solid #1F3B2A;display:grid;place-items:center;margin:0 auto 18px;box-shadow:0 0 18px rgba(46,229,122,.22)}
.logo svg{width:26px;height:26px}
h1{font-size:21px;font-weight:700;text-align:center;letter-spacing:-.01em}
.sub{color:var(--muted);text-align:center;font-size:13.5px;margin-top:6px;line-height:1.5}
form{margin-top:26px;display:flex;flex-direction:column;gap:14px}
label{font-size:12.5px;color:var(--muted);font-weight:500;display:block;margin-bottom:6px}
input{width:100%;padding:13px 14px;border:1.5px solid var(--line);border-radius:10px;background:#0A100C;
color:var(--text);font:inherit;font-size:14px}
input:focus{outline:none;border-color:var(--teal2);box-shadow:0 0 0 4px var(--soft)}
button{margin-top:4px;padding:13px;border:0;border-radius:10px;font:inherit;font-weight:700;cursor:pointer;
background:linear-gradient(135deg,var(--teal),var(--teal2));color:#03120A;box-shadow:0 4px 16px rgba(46,229,122,.25)}
button:hover{filter:brightness(.95)}
.alert{background:#2A1213;border:1px solid #5A2023;color:#FF9A9A;border-radius:10px;padding:11px 14px;font-size:13.5px}
.hint{background:var(--soft);border:1px solid #1F3B2A;color:var(--teal2);border-radius:10px;padding:11px 14px;font-size:12.5px;line-height:1.5}
.card{background:var(--card);border:1px solid var(--line);border-radius:18px;padding:30px 28px;box-shadow:0 1px 2px rgba(0,0,0,.5),0 8px 24px rgba(0,0,0,.35)}
.pwrap{position:relative}
.pwrap input{padding-right:44px}
.pwtoggle{position:absolute;right:10px;top:50%;transform:translateY(calc(-50% + 11px));background:none;border:0;
  box-shadow:none;padding:4px;min-height:auto;color:var(--muted);cursor:pointer;font-size:11.5px;font-weight:600}
.pwtoggle:hover{color:var(--teal2)}
</style>
</head>
<body>
<canvas id="globe" aria-hidden="true"></canvas>
<div class="box">
  <div class="logo" aria-hidden="true">
    <svg viewBox="0 0 40 40" fill="none" stroke="url(#lg)" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
      <defs><linearGradient id="lg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#7CF0A6"/><stop offset="1" stop-color="#16A34A"/></linearGradient></defs>
      <path d="M20 4.5l12 4.2v9.6c0 7.4-5 12.4-12 15.2-7-2.8-12-7.8-12-15.2V8.7l12-4.2z"/>
      <circle cx="19" cy="17.5" r="5"/><path d="M22.8 21.3l4.2 4.2"/><path d="M16.5 17.5h5" stroke-width="1.6"/>
    </svg>
  </div>
  <h1><?= $setup ? 'Create your admin account' : 'Sign in' ?></h1>
  <p class="sub"><?= $setup ? 'No account exists yet. Set a username and password to protect this scanner.' : 'SQLi Scanner dashboard' ?></p>
  <div class="card">
    <?php if ($error): ?><div class="alert" style="margin-bottom:16px"><?= h($error) ?></div><?php endif; ?>
    <form method="post">
      <div><label for="u">Username</label><input id="u" name="username" value="<?= h($_POST['username'] ?? '') ?>" required autofocus></div>
      <?php if ($setup): ?>
        <div><label for="e">Email</label><input id="e" type="email" name="email" value="<?= h($_POST['email'] ?? '') ?>" required></div>
      <?php endif; ?>
      <div><label for="p">Password</label><div class="pwrap"><input id="p" type="password" name="password" required><button type="button" class="pwtoggle" onclick="togglePw(this)">Show</button></div></div>
      <?php if ($setup): ?>
        <div><label for="p2">Confirm password</label><div class="pwrap"><input id="p2" type="password" name="password2" required><button type="button" class="pwtoggle" onclick="togglePw(this)">Show</button></div></div>
      <?php endif; ?>
      <button type="submit"><?= $setup ? 'Create account' : 'Sign in' ?></button>
    </form>
    <?php if ($setup): ?><p class="hint" style="margin-top:16px">This runs once. The account details are saved only on this server, in <code>auth_data.json</code>.</p><?php endif; ?>
  </div>
</div>
<script>
function togglePw(btn){
  var input = btn.previousElementSibling;
  if (input.type === 'password') { input.type = 'text'; btn.textContent = 'Hide'; }
  else { input.type = 'password'; btn.textContent = 'Show'; }
}

(function () {
  var canvas = document.getElementById('globe');
  var ctx = canvas.getContext('2d');
  var reduceMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  var W, H, DPR = Math.min(window.devicePixelRatio || 1, 2);

  function resize() {
    W = canvas.width = Math.floor(window.innerWidth * DPR);
    H = canvas.height = Math.floor(window.innerHeight * DPR);
    canvas.style.width = window.innerWidth + 'px';
    canvas.style.height = window.innerHeight + 'px';
  }
  resize();
  window.addEventListener('resize', resize);

  var N = 650, pts = [];
  var golden = Math.PI * (3 - Math.sqrt(5));
  for (var i = 0; i < N; i++) {
    var y = 1 - (i / (N - 1)) * 2;
    var r = Math.sqrt(Math.max(0, 1 - y * y));
    var theta = golden * i;
    pts.push([Math.cos(theta) * r, y, Math.sin(theta) * r]);
  }

  var angleY = 0, angleX = 0.35;
  var LINK_DIST = 0.34;

  function frame() {
    var cx = W / 2, cy = H / 2;
    var radius = Math.min(W, H) * 0.62;
    ctx.clearRect(0, 0, W, H);

    var cosY = Math.cos(angleY), sinY = Math.sin(angleY);
    var cosX = Math.cos(angleX), sinX = Math.sin(angleX);
    var proj = new Array(N);

    for (var i = 0; i < N; i++) {
      var p = pts[i];
      var x1 = p[0] * cosY - p[2] * sinY;
      var z1 = p[0] * sinY + p[2] * cosY;
      var y1 = p[1];
      var y2 = y1 * cosX - z1 * sinX;
      var z2 = y1 * sinX + z1 * cosX;

      var scale = 1 / (2 - z2);
      var sx = cx + x1 * radius * scale;
      var sy = cy + y2 * radius * scale;
      proj[i] = [sx, sy, z2, scale];
    }

    ctx.lineWidth = 1 * DPR;
    for (var i = 0; i < N; i++) {
      var a = pts[i];
      for (var j = i + 1; j < N; j++) {
        var b = pts[j];
        var dx = a[0] - b[0], dy = a[1] - b[1], dz = a[2] - b[2];
        var d = Math.sqrt(dx * dx + dy * dy + dz * dz);
        if (d < LINK_DIST) {
          var A = proj[i], B = proj[j];
          var frontness = (A[2] + B[2]) / 2;
          if (frontness < -0.15) continue;
          var alpha = Math.max(0, (frontness + 1) / 2) * 0.22;
          ctx.strokeStyle = 'rgba(46,229,122,' + alpha.toFixed(3) + ')';
          ctx.beginPath();
          ctx.moveTo(A[0], A[1]);
          ctx.lineTo(B[0], B[1]);
          ctx.stroke();
        }
      }
    }

    for (var i = 0; i < N; i++) {
      var P = proj[i];
      var front = (P[2] + 1) / 2;
      var alpha = 0.15 + front * 0.65;
      var size = (0.9 + front * 1.6) * DPR;
      ctx.beginPath();
      ctx.fillStyle = 'rgba(126,240,166,' + alpha.toFixed(3) + ')';
      ctx.arc(P[0], P[1], size, 0, Math.PI * 2);
      ctx.fill();
    }

    if (!reduceMotion) angleY += 0.0022;
    requestAnimationFrame(frame);
  }
  requestAnimationFrame(frame);
})();
</script>
</body>
</html>
