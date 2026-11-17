// Delete page: the deletion token arrives in the fragment, never in the path.

import { HushApi } from '../client/api.js';
import { idFromPath, tokenFromFragment } from '../client/links.js';
import { byId, describeError, hide, setText, show } from '../ui/dom.js';

const statusLine = byId('delete-status', HTMLParagraphElement);
const button = byId('delete-button', HTMLButtonElement);
const errorBox = byId('delete-error', HTMLParagraphElement);

/** @param {string} message */
function fail(message) {
  setText(errorBox, message);
  show(errorBox);
}

let id = '';
let token = '';
try {
  id = idFromPath(location.pathname, 'd');
  token = tokenFromFragment(location.hash);
} catch (error) {
  button.disabled = true;
  fail(describeError(error));
}

button.addEventListener('click', async () => {
  hide(errorBox);
  button.disabled = true;
  try {
    await new HushApi().remove(id, token);
    history.replaceState(null, '', location.pathname);
    setText(statusLine, 'Deleted. The ciphertext is gone from the server and the link no longer works.');
    hide(button);
  } catch (error) {
    button.disabled = false;
    fail(describeError(error));
  }
});
