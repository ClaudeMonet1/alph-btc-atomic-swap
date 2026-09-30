// In-page replacements for alert/confirm/prompt: the native dialogs block the
// page (a peer's message can arrive while one is open), look poor on phones and
// cannot show a password field. Each call builds a fresh overlay and removes it
// on close; ids: modal, modal-msg, modal-input, modal-ok, modal-cancel.
function open({ message, input = false, password = false, okText = 'OK', cancelText = null, placeholder = '' }) {
  return new Promise((resolve) => {
    const overlay = document.createElement('div');
    overlay.id = 'modal';
    overlay.className = 'modal-overlay';
    overlay.innerHTML = `<div class="modal-box" role="dialog" aria-modal="true">
      <div id="modal-msg" class="modal-msg"></div>
      ${input ? `<input id="modal-input" class="modal-input" type="${password ? 'password' : 'text'}" autocomplete="${password ? 'current-password' : 'off'}" placeholder="${placeholder}">` : ''}
      <div class="modal-actions">${cancelText ? `<button id="modal-cancel" class="sm">${cancelText}</button>` : ''}<button id="modal-ok" class="sm primary">${okText}</button></div>
    </div>`;
    overlay.querySelector('#modal-msg').textContent = message;
    const done = (value) => { overlay.remove(); document.removeEventListener('keydown', onKey); resolve(value); };
    const ok = () => done(input ? overlay.querySelector('#modal-input').value : true);
    const cancel = () => done(input ? null : false);
    const onKey = (e) => { if (e.key === 'Escape' && cancelText) cancel(); if (e.key === 'Enter' && (input || !cancelText)) ok(); };
    overlay.querySelector('#modal-ok').addEventListener('click', ok);
    overlay.querySelector('#modal-cancel')?.addEventListener('click', cancel);
    document.addEventListener('keydown', onKey);
    document.body.appendChild(overlay);
    (overlay.querySelector('#modal-input') || overlay.querySelector('#modal-ok')).focus();
  });
}
export const modalAlert = (message) => open({ message });
export const modalConfirm = (message, okText = 'OK') => open({ message, okText, cancelText: 'Cancel' });
export const modalPrompt = (message, { password = false, placeholder = '' } = {}) => open({ message, input: true, password, placeholder, cancelText: 'Cancel' });
