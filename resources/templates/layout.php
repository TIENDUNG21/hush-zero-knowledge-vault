<?php

declare(strict_types=1);

/** @var array<string, string|int|bool|null> $v */
/** @var Closure(string|int|bool|null): string $e */
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="referrer" content="no-referrer">
  <meta name="robots" content="noindex, nofollow">
  <meta name="color-scheme" content="dark">
  <title><?= $e($v['title'] ?? 'Hush') ?> - Hush</title>
  <link rel="icon" href="/assets/img/logo.svg" type="image/svg+xml">
  <link rel="stylesheet" href="/assets/css/hush.css">
<?php if (is_string($v['script'] ?? null)) { ?>
  <script type="module" src="/assets/js/pages/<?= $e($v['script']) ?>.js"></script>
<?php } ?>
</head>
<body>
  <header class="topbar">
    <a class="brand" href="/" aria-label="Hush home">
      <svg viewBox="0 0 64 64" width="28" height="28" aria-hidden="true">
        <rect x="5" y="5" width="54" height="54" rx="14" fill="none" stroke="#3fb950" stroke-width="5"/>
        <circle cx="32" cy="27" r="8" fill="#3fb950"/>
        <path d="M28.2 31h7.6l2.6 15h-12.8z" fill="#3fb950"/>
      </svg>
      <span>Hush</span>
    </a>
    <span class="topbar-note">zero-knowledge secret sharing</span>
  </header>
  <main class="shell">
<?= (string) ($v['content'] ?? '') ?>
  </main>
  <footer class="foot">
    <p>Encrypted in your browser with AES-256-GCM before upload. The key travels after the <code>#</code> in the link, the part of a URL that browsers never send to the server.</p>
    <noscript><p class="error">Hush needs JavaScript: encryption happens in this page, not on the server.</p></noscript>
  </footer>
</body>
</html>
