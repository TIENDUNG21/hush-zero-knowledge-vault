// View page: check the link without spending a view, then reveal on request.

import { EnvelopeError } from '../core/format.js';
import { ApiError, HushApi } from '../client/api.js';
import { idFromPath, keyFromFragment } from '../client/links.js';
import { inspectSecret, revealSecret } from '../client/transfer.js';
import {
  byId,
  copyText,
  describeError,
  fillFacts,
  flash,
  formatBytes,
  formatTime,
  hide,
  setText,
  show,
  viewsPhrase,
} from '../ui/dom.js';

const statusLine = byId('view-status', HTMLParagraphElement);
const locked = byId('view-locked', HTMLDivElement);
const facts = byId('facts', HTMLElement);
const passwordField = byId('password-field', HTMLLabelElement);
const passwordInput = byId('view-password', HTMLInputElement);
const revealButton = byId('reveal-button', HTMLButtonElement);
const burnWarning = byId('burn-warning', HTMLParagraphElement);
const revealed = byId('view-revealed', HTMLDivElement);
const revealedText = byId('revealed-text', HTMLDivElement);
const secretOutput = byId('secret-output', HTMLPreElement);
const copySecret = byId('copy-secret', HTMLButtonElement);
const revealedFile = byId('revealed-file', HTMLDivElement);
const downloadInfo = byId('download-info', HTMLParagraphElement);
const downloadLink = byId('download-link', HTMLAnchorElement);
const afterReveal = byId('after-reveal', HTMLParagraphElement);
const errorBox = byId('view-error', HTMLParagraphElement);

const api = new HushApi();

/** @param {string} message */
function fail(message) {
  hide(locked);
  setText(statusLine, 'This secret cannot be opened.');
  setText(errorBox, message);
  show(errorBox);
}

/**
 * @param {import('../client/api.js').Status} status
 * @param {import('../core/format.js').Meta | null} meta
 */
function describe(status, meta) {
  /** @type {Array<[string, string]>} */
  const rows = [];
  if (meta) {
    rows.push(['Contains', meta.kind === 'text' ? `text (${formatBytes(meta.size)})` : `file: ${meta.name ?? 'unnamed'} (${formatBytes(meta.size)})`]);
  } else {
    rows.push(['Contains', 'hidden until the password is entered']);
  }
  rows.push(['Expires', formatTime(status.expiresAt)]);
  rows.push(['Views left', String(status.viewsLeft)]);
  fillFacts(facts, rows);
  setText(burnWarning, status.viewsLeft === 1
    ? 'This is the last view: after you reveal it, the secret is deleted from the server.'
    : `Revealing uses one of ${status.viewsLeft} remaining views.`);
}

async function start() {
  let id;
  let key;
  try {
    id = idFromPath(location.pathname, 's');
    key = keyFromFragment(location.hash);
  } catch (error) {
    fail(describeError(error));
    return;
  }

  /** @type {import('../client/api.js').Status} */
  let status;
  /** @type {import('../core/format.js').Meta | null} */
  let meta = null;
  try {
    status = await api.status(id);
    if (!status.passwordProtected) {
      // Verify the link key on the metadata before any view is spent.
      meta = (await inspectSecret(api, id, key, null)).meta;
    }
  } catch (error) {
    fail(describeError(error));
    return;
  }

  setText(statusLine, status.passwordProtected
    ? 'The sender protected this secret with a password.'
    : 'Ready. Nothing has been decrypted or counted yet.');
  passwordField.hidden = !status.passwordProtected;
  describe(status, meta);
  show(locked);
  (status.passwordProtected ? passwordInput : revealButton).focus();

  const reveal = async () => {
    hide(errorBox);
    revealButton.disabled = true;
    const password = status.passwordProtected ? passwordInput.value : null;
    try {
      if (status.passwordProtected) {
        setText(revealButton, 'Checking password...');
        // Wrong passwords are caught here, before the view is consumed.
        await inspectSecret(api, id, key, password);
      }
      setText(revealButton, 'Decrypting...');
      const { opened, viewsLeft } = await revealSecret(api, id, key, password);
      hide(locked);
      if (opened.kind === 'text') {
        setText(secretOutput, opened.text ?? '');
        show(revealedText);
      } else {
        const url = URL.createObjectURL(new Blob([opened.data], { type: opened.type ?? 'application/octet-stream' }));
        downloadLink.href = url;
        downloadLink.download = opened.name ?? 'secret.bin';
        setText(downloadInfo, `${opened.name ?? 'secret.bin'} - ${formatBytes(opened.data.length)}`);
        show(revealedFile);
      }
      setText(statusLine, 'Decrypted in this browser.');
      setText(afterReveal, viewsLeft === 0
        ? 'This was the last view. The ciphertext has been deleted from the server, so save what you need now.'
        : `It can be opened ${viewsPhrase(viewsLeft)} more before it is deleted.`);
      show(revealed);
      // Keep the key out of the address bar now that it has been used.
      history.replaceState(null, '', location.pathname);
    } catch (error) {
      setText(revealButton, 'Reveal secret');
      revealButton.disabled = false;
      if (error instanceof EnvelopeError && error.reason === 'authentication' && status.passwordProtected) {
        setText(errorBox, 'Wrong password. No view was used; try again.');
        show(errorBox);
        passwordInput.select();
        return;
      }
      if (error instanceof ApiError && error.code === 'not_found') {
        fail(describeError(error));
        return;
      }
      setText(errorBox, describeError(error));
      show(errorBox);
    }
  };

  revealButton.addEventListener('click', reveal);
  passwordInput.addEventListener('keydown', (event) => {
    if (event.key === 'Enter') {
      event.preventDefault();
      void reveal();
    }
  });
}

copySecret.addEventListener('click', async () => {
  flash(copySecret, (await copyText(secretOutput.textContent ?? '')) ? 'Copied' : 'Select and copy');
});

void start();
