<?php

declare(strict_types=1);

/** @var array<string, string|int|bool|null> $v */
/** @var Closure(string|int|bool|null): string $e */
?>
<section class="card" id="delete">
  <h1>Delete a secret</h1>
  <p class="lede" id="delete-status">This removes the ciphertext from the server now, whether or not it has been opened.</p>
  <button type="button" class="danger" id="delete-button">Delete now</button>
  <p class="error" id="delete-error" role="alert" hidden></p>
</section>
