<?php

declare(strict_types=1);

/** @var array<string, string|int|bool|null> $v */
/** @var Closure(string|int|bool|null): string $e */
?>
<section class="card" id="create" data-max-bytes="<?= $e($v['maxBytes'] ?? 0) ?>">
  <h1>Share a secret</h1>
  <p class="lede">Text or a file, encrypted on this device. The server stores ciphertext it cannot read and deletes it after the last view.</p>

  <form id="create-form" autocomplete="off" novalidate>
    <div class="tabs" role="tablist" aria-label="What to share">
      <button type="button" role="tab" id="tab-text" aria-controls="panel-text" aria-selected="true">Text</button>
      <button type="button" role="tab" id="tab-file" aria-controls="panel-file" aria-selected="false">File</button>
    </div>

    <div id="panel-text" role="tabpanel" aria-labelledby="tab-text">
      <label class="field" for="secret-text">Secret
        <textarea id="secret-text" rows="7" spellcheck="false" placeholder="Passwords, API keys, recovery codes, notes..."></textarea>
      </label>
    </div>

    <div id="panel-file" role="tabpanel" aria-labelledby="tab-file" hidden>
      <label class="dropzone" id="dropzone" for="secret-file">
        <input type="file" id="secret-file">
        <span class="dropzone-title">Drop a file here or <u>choose one</u></span>
        <span class="dropzone-hint" id="file-limit"></span>
      </label>
      <p class="file-info" id="file-info" hidden></p>
    </div>

    <div class="options">
      <label class="field" for="expires">Expires after
        <select id="expires">
          <option value="300">5 minutes</option>
          <option value="3600">1 hour</option>
          <option value="86400" selected>1 day</option>
          <option value="604800">7 days</option>
        </select>
      </label>
      <label class="field" for="views">Can be opened
        <select id="views">
          <option value="1" selected>once, then burned</option>
          <option value="2">2 times</option>
          <option value="3">3 times</option>
          <option value="5">5 times</option>
          <option value="10">10 times</option>
        </select>
      </label>
      <label class="field" for="password"><span class="label-text">Password <span class="optional">optional</span></span>
        <input type="password" id="password" autocomplete="new-password" spellcheck="false">
      </label>
    </div>

    <button type="submit" class="primary" id="create-button">Encrypt and create link</button>
    <div class="progress-row" id="progress-row" hidden>
      <progress id="progress" max="1" value="0"></progress>
      <span id="progress-label"></span>
    </div>
    <p class="error" id="create-error" role="alert" hidden></p>
  </form>

  <div id="result" hidden>
    <h2>Your link is ready</h2>
    <label class="field" for="share-link">Send this link
      <span class="copy-row">
        <input id="share-link" readonly spellcheck="false">
        <button type="button" class="secondary" data-copy="share-link">Copy</button>
      </span>
    </label>
    <p class="hint" id="result-summary"></p>
    <label class="field" for="delete-link"><span class="label-text">Delete link <span class="optional">keep it to yourself</span></span>
      <span class="copy-row">
        <input id="delete-link" readonly spellcheck="false">
        <button type="button" class="secondary" data-copy="delete-link">Copy</button>
      </span>
    </label>
    <details class="server-view">
      <summary>What the server received</summary>
      <dl id="server-view"></dl>
    </details>
    <button type="button" class="secondary" id="create-another">Share another secret</button>
  </div>
</section>
