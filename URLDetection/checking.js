(function(){
  const params = new URLSearchParams(location.search);
  const target = params.get('target') || '';
  document.getElementById('targetUrl').textContent = target;

  // Ask background to check the URL
  chrome.runtime.sendMessage({ action: 'checkUrl', url: target }, (resp) => {
    if (!resp || !resp.verdict) {
      // On error, allow to proceed
      return chrome.runtime.sendMessage({ action: 'proceedToUrl', url: target });
    }

    const verdict = resp.verdict;
    // Block for unsafe or suspicious verdicts
    if (verdict === 'phishing' || verdict === 'malicious' || verdict === 'suspicious') {
      // Show warning UI instead of proceeding
      const warnUrl = chrome.runtime.getURL(`warning.html?target=${encodeURIComponent(target)}&v=${encodeURIComponent(verdict)}`);
      location.replace(warnUrl);
    } else {
      // safe/unknown/error/suspicious -> proceed
      chrome.runtime.sendMessage({ action: 'proceedToUrl', url: target });
    }
  });

  // Fallback actions if something stalls
  const proceedBtn = document.getElementById('proceedNow');
  const closeBtn = document.getElementById('closeTab');
  const fallback = document.getElementById('fallbackActions');
  let fallbackTimer = setTimeout(() => {
    fallback.style.display = 'flex';
  }, 7000);

  proceedBtn.addEventListener('click', () => {
    clearTimeout(fallbackTimer);
    chrome.runtime.sendMessage({ action: 'proceedToUrl', url: target });
  });
  closeBtn.addEventListener('click', () => {
    clearTimeout(fallbackTimer);
    chrome.runtime.sendMessage({ action: 'closeCurrentTab' });
  });
})();
