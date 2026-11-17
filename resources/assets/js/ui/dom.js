// Small DOM helpers. Everything writes text with textContent: the CSP
// enforces Trusted Types, so HTML sinks such as innerHTML would throw.

import { EnvelopeError } from '../core/format.js';
import { ApiError } from '../client/api.js';
import { LinkError } from '../client/links.js';

/**
 * @template {HTMLElement} T
 * @param {string} id
 * @param {new () => T} type
 * @returns {T}
 */
export function byId(id, type) {
  const element = document.getElementById(id);
  if (!(element instanceof type)) {
    throw new Error(`#${id} is missing or not a ${type.name}`);
  }
  return element;
}

/** @param {HTMLElement} element @param {string} text */
export function setText(element, text) {
  element.textContent = text;
}

/** @param {...HTMLElement} elements */
export function show(...elements) {
  for (const element of elements) {
    element.hidden = false;
  }
}

/** @param {...HTMLElement} elements */
export function hide(...elements) {
  for (const element of elements) {
    element.hidden = true;
  }
}

/**
 * Replaces the children of a <dl> with term/description pairs.
 * @param {HTMLElement} list
 * @param {Array<[string, string]>} rows
 */
export function fillFacts(list, rows) {
  list.replaceChildren();
  for (const [term, description] of rows) {
    const dt = document.createElement('dt');
    dt.textContent = term;
    const dd = document.createElement('dd');
    dd.textContent = description;
    list.append(dt, dd);
  }
}

/**
 * @param {number} bytes
 * @returns {string}
 */
export function formatBytes(bytes) {
  if (bytes < 1024) {
    return `${bytes} B`;
  }
  const units = ['KiB', 'MiB', 'GiB'];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  return `${value.toFixed(value < 10 ? 1 : 0)} ${units[unit]}`;
}

/**
 * @param {number} unixSeconds
 * @returns {string}
 */
export function formatTime(unixSeconds) {
  return new Date(unixSeconds * 1000).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

/**
 * @param {number} views
 * @returns {string}
 */
export function viewsPhrase(views) {
  return views === 1 ? 'once' : `${views} times`;
}

/**
 * Copies text to the clipboard; falls back to selecting an input.
 * @param {string} text
 * @param {HTMLInputElement | null} [input]
 * @returns {Promise<boolean>}
 */
export async function copyText(text, input = null) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    input?.select();
    return false;
  }
}

/**
 * Wires every button with data-copy="<input id>".
 * @param {ParentNode} root
 */
export function wireCopyButtons(root) {
  for (const button of root.querySelectorAll('button[data-copy]')) {
    if (!(button instanceof HTMLButtonElement)) {
      continue;
    }
    button.addEventListener('click', async () => {
      const input = byId(button.dataset.copy ?? '', HTMLInputElement);
      const copied = await copyText(input.value, input);
      flash(button, copied ? 'Copied' : 'Press Ctrl+C');
    });
  }
}

/**
 * @param {HTMLButtonElement} button
 * @param {string} label
 */
export function flash(button, label) {
  const original = button.dataset.label ?? button.textContent ?? '';
  button.dataset.label = original;
  button.textContent = label;
  setTimeout(() => {
    button.textContent = original;
  }, 1600);
}

/**
 * A sentence a person can act on, for any error the flows can raise.
 * @param {unknown} error
 * @returns {string}
 */
export function describeError(error) {
  if (error instanceof LinkError) {
    return error.message;
  }
  if (error instanceof EnvelopeError) {
    switch (error.reason) {
      case 'authentication':
        return 'This link and password do not open the secret. Check the password, or ask for the complete link.';
      case 'password_required':
        return 'Enter the password the sender gave you.';
      case 'unsupported':
        return error.message;
      default:
        return 'The encrypted data is damaged and cannot be opened.';
    }
  }
  if (error instanceof ApiError) {
    switch (error.code) {
      case 'not_found':
        return 'This secret does not exist, has expired, or has already been viewed.';
      case 'rate_limited':
        return 'Too many requests from your network. Wait a minute and try again.';
      case 'secret_too_large':
      case 'payload_too_large':
        return 'This is larger than the server accepts.';
      case 'network':
        return 'Could not reach the server. Check your connection and try again.';
      default:
        return error.message;
    }
  }
  return error instanceof Error ? error.message : 'Something went wrong.';
}
