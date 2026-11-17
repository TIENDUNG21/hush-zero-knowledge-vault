// Create page: encrypt locally, upload ciphertext, show the share link.

import { sealSecret } from '../core/crypto.js';
import { reservedBytes, safeFileMeta } from '../core/format.js';
import { HushApi } from '../client/api.js';
import { buildDeleteLink, buildShareLink } from '../client/links.js';
import { uploadSealed } from '../client/transfer.js';
import {
  byId,
  describeError,
  fillFacts,
  formatBytes,
  formatTime,
  hide,
  setText,
  show,
  viewsPhrase,
  wireCopyButtons,
} from '../ui/dom.js';

const section = byId('create', HTMLElement);
const form = byId('create-form', HTMLFormElement);
const tabText = byId('tab-text', HTMLButtonElement);
const tabFile = byId('tab-file', HTMLButtonElement);
const panelText = byId('panel-text', HTMLDivElement);
const panelFile = byId('panel-file', HTMLDivElement);
const textInput = byId('secret-text', HTMLTextAreaElement);
const fileInput = byId('secret-file', HTMLInputElement);
const dropzone = byId('dropzone', HTMLLabelElement);
const fileInfo = byId('file-info', HTMLParagraphElement);
const fileLimit = byId('file-limit', HTMLSpanElement);
const expires = byId('expires', HTMLSelectElement);
const views = byId('views', HTMLSelectElement);
const password = byId('password', HTMLInputElement);
const button = byId('create-button', HTMLButtonElement);
const progressRow = byId('progress-row', HTMLDivElement);
const progress = byId('progress', HTMLProgressElement);
const progressLabel = byId('progress-label', HTMLSpanElement);
const errorBox = byId('create-error', HTMLParagraphElement);
const result = byId('result', HTMLDivElement);
const shareLink = byId('share-link', HTMLInputElement);
const deleteLink = byId('delete-link', HTMLInputElement);
const summary = byId('result-summary', HTMLParagraphElement);
const serverView = byId('server-view', HTMLElement);
const another = byId('create-another', HTMLButtonElement);

const maxBytes = Number(section.dataset.maxBytes ?? '0');
const api = new HushApi();
/** @type {'text' | 'file'} */
let mode = 'text';
/** @type {File | null} */
let chosenFile = null;

setText(fileLimit, `Up to ${formatBytes(maxBytes)}. Name and type are encrypted too.`);
wireCopyButtons(result);

/** @param {'text' | 'file'} next */
function selectTab(next) {
  mode = next;
  tabText.setAttribute('aria-selected', String(next === 'text'));
  tabFile.setAttribute('aria-selected', String(next === 'file'));
  panelText.hidden = next !== 'text';
  panelFile.hidden = next !== 'file';
  hide(errorBox);
}

tabText.addEventListener('click', () => selectTab('text'));
tabFile.addEventListener('click', () => selectTab('file'));

/** @param {File | null} file */
function chooseFile(file) {
  chosenFile = file;
  hide(errorBox);
  if (!file) {
    hide(fileInfo);
    return;
  }
  setText(fileInfo, `${file.name} - ${formatBytes(file.size)}`);
  show(fileInfo);
  if (reservedBytes(file.size) > maxBytes) {
    showError(`This file is ${formatBytes(file.size)}; the server accepts up to ${formatBytes(maxBytes)}.`);
  }
}

fileInput.addEventListener('change', () => chooseFile(fileInput.files?.[0] ?? null));
for (const type of ['dragenter', 'dragover']) {
  dropzone.addEventListener(type, (event) => {
    event.preventDefault();
    dropzone.classList.add('dragging');
  });
}
for (const type of ['dragleave', 'drop']) {
  dropzone.addEventListener(type, () => dropzone.classList.remove('dragging'));
}
dropzone.addEventListener('drop', (event) => {
  event.preventDefault();
  chooseFile(event.dataTransfer?.files?.[0] ?? null);
});

/** @param {string} message */
function showError(message) {
  setText(errorBox, message);
  show(errorBox);
}

/** @param {number} done @param {number} total */
function onProgress(done, total) {
  progress.value = total === 0 ? 1 : done / total;
  setText(progressLabel, total > 1 ? `Uploading ${done} of ${total} encrypted chunks` : 'Uploading ciphertext');
}

form.addEventListener('submit', async (event) => {
  // The CSP has form-action 'none': without this handler nothing is ever posted.
  event.preventDefault();
  hide(errorBox);

  /** @type {import('../core/crypto.js').PlainInput} */
  let input;
  if (mode === 'text') {
    if (textInput.value === '') {
      showError('Type or paste the secret first.');
      return;
    }
    input = { kind: 'text', text: textInput.value };
  } else {
    if (!chosenFile) {
      showError('Choose a file first.');
      return;
    }
    if (reservedBytes(chosenFile.size) > maxBytes) {
      showError(`This file is larger than the ${formatBytes(maxBytes)} the server accepts.`);
      return;
    }
    const { name, type } = safeFileMeta(chosenFile.name, chosenFile.type);
    input = { kind: 'file', data: new Uint8Array(await chosenFile.arrayBuffer()), name, type };
  }

  button.disabled = true;
  show(progressRow);
  progress.removeAttribute('value');
  setText(progressLabel, password.value !== '' ? 'Deriving a key from the password' : 'Encrypting');

  try {
    const sealed = await sealSecret(input, password.value !== '' ? { password: password.value } : {});
    const maxViews = Number(views.value);
    const created = await uploadSealed(api, sealed, { expiresIn: Number(expires.value), maxViews, onProgress });

    shareLink.value = buildShareLink(location.origin, created.id, sealed.fragmentKey);
    deleteLink.value = buildDeleteLink(location.origin, created.id, created.deletionToken);
    setText(summary, `It can be opened ${viewsPhrase(maxViews)} until ${formatTime(created.expiresAt)}${sealed.header.passwordProtected ? ', with the password you chose. Send the password another way.' : '.'}`);

    fillFacts(serverView, [
      ['Secret id', created.id],
      ['Ciphertext', `${formatBytes(sealed.ciphertextBytes)} in ${sealed.chunkCount} chunk${sealed.chunkCount === 1 ? '' : 's'} (padded to 256-byte blocks)`],
      ['Public header', `${sealed.headerBytes.length} bytes: sizes and salt${sealed.header.passwordProtected ? ', PBKDF2 iterations' : ''}`],
      ['Link key', 'not sent; it stays after the # in the link'],
      ['Password', sealed.header.passwordProtected ? 'not sent; only used to derive the key here' : 'none'],
      ['Also visible', 'your IP address and the time of each request'],
    ]);

    // Drop the plaintext from the page now that it is no longer needed.
    textInput.value = '';
    password.value = '';
    fileInput.value = '';
    chooseFile(null);
    hide(form);
    show(result);
    shareLink.focus();
    shareLink.select();
  } catch (error) {
    showError(describeError(error));
  } finally {
    button.disabled = false;
    hide(progressRow);
  }
});

another.addEventListener('click', () => {
  shareLink.value = '';
  deleteLink.value = '';
  hide(result);
  show(form);
  selectTab(mode);
  textInput.focus();
});
