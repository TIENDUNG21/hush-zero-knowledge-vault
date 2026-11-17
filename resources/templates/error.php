<?php

declare(strict_types=1);

/** @var array<string, string|int|bool|null> $v */
/** @var Closure(string|int|bool|null): string $e */
?>
<section class="card">
  <p class="status-code"><?= $e($v['status'] ?? 500) ?></p>
  <h1><?= $e($v['title'] ?? 'Error') ?></h1>
  <p class="lede"><?= $e($v['message'] ?? '') ?></p>
  <a class="button secondary" href="/">Share a secret</a>
</section>
