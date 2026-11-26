<?php
// Shared authentication helper. Include this at the top of any page that needs a login.
// Single-account model: the first visit to login.php creates the one admin account.
// There is no public sign-up page.
if (session_status() === PHP_SESSION_NONE) session_start();

if (!function_exists('h')) {
    function h($s): string { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }
}

define('AUTH_STORE', __DIR__ . '/auth_data.json');

function auth_load(): ?array {
    if (!file_exists(AUTH_STORE)) return null;
    $d = json_decode(file_get_contents(AUTH_STORE), true);
    return is_array($d) ? $d : null;
}

function auth_save(string $username, string $email, string $password): void {
    file_put_contents(AUTH_STORE, json_encode([
        'username' => $username,
        'email' => $email,
        'hash' => password_hash($password, PASSWORD_DEFAULT),
        'created' => date('Y-m-d'),
    ]));
}

function has_account(): bool { return auth_load() !== null; }

function current_user(): ?string { return $_SESSION['user'] ?? null; }

function current_account(): ?array { return current_user() ? auth_load() : null; }

function require_login(): void {
    if (!has_account()) { header('Location: login.php'); exit; }
    if (!current_user()) {
        $_SESSION['redirect_after_login'] = $_SERVER['REQUEST_URI'] ?? 'index.php';
        header('Location: login.php');
        exit;
    }
}

function attempt_login(string $username, string $password): bool {
    $acc = auth_load();
    if ($acc && hash_equals($acc['username'], $username) && password_verify($password, $acc['hash'])) {
        session_regenerate_id(true);
        $_SESSION['user'] = $username;
        return true;
    }
    return false;
}
