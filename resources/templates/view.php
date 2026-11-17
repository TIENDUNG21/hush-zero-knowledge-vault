<?php

declare(strict_types=1);

/** @var array<string, string|int|bool|null> $v */
/** @var Closure(string|int|bool|null): string $e */
?>
<section class="card" id="view">
  <h1>Someone shared a secret with you</h1>
  <p class="lede" id="view-status" aria-live="polite">Checking the link...</p>

  <div id="view-locked" hidden>
    <dl class="facts" id="facts"></dl>
    <label class="field" for="view-password" id="password-field" hidden>This secret has a password
      <input type="password" id="view-password" autocomplete="off" spellcheck="false">
    </label>
    <button type="button" class="primary" id="reveal-button">Reveal secret</button>
    <p class="hint" id="burn-warning"></p>
  </div>

  <div id="view-revealed" hidden>
    <div id="revealed-text" hidden>
      <pre class="secret" id="secret-output" tabindex="0"></pre>
      <button type="button" class="secondary" id="copy-secret">Copy</button>
    </div>
    <div id="revealed-file" hidden>
      <p class="file-info" id="download-info"></p>
      <a class="button primary" id="download-link" href="#">Save file</a>
    </div>
    <p class="hint" id="after-reveal"></p>
  </div>

  <p class="error" id="view-error" role="alert" hidden></p>
</section>
