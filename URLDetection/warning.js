document.addEventListener('DOMContentLoaded', () => {
  // Read query params and populate the UI
  const params = new URLSearchParams(location.search);
  const target = params.get('target') || '';
  const verdict = params.get('v') || 'suspicious';

  const targetEl = document.getElementById('target');
  const verdictEl = document.getElementById('verdict');
  if (targetEl) targetEl.textContent = target;
  if (verdictEl) verdictEl.textContent = verdict;

  // Wire up buttons to background actions
  const proceedBtn = document.getElementById('proceed');
  const closeBtn = document.getElementById('close');

  if (proceedBtn) {
    proceedBtn.addEventListener('click', () => {
      if (target) {
        chrome.runtime.sendMessage({ action: 'proceedToUrl', url: target });
      }
    });
  }

  if (closeBtn) {
    closeBtn.addEventListener('click', () => {
      chrome.runtime.sendMessage({ action: 'closeCurrentTab' });
    });
  }
});
