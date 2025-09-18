// const SERVER_URL = "http://127.0.0.1:5000/check_url"; // Flask server

// chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
//   const url = details.url;

//   try {
//     let response = await fetch(SERVER_URL, {
//       method: "POST",
//       headers: { "Content-Type": "application/json" },
//       body: JSON.stringify({ url: url })
//     });

//     let data = await response.json();
//     console.log("Server verdict:", data);

//     if (data.verdict === "phishing" || data.verdict === "suspicious") {
//       await chrome.storage.local.set({ blockedUrl: url });

//       // Show warning popup
//       chrome.windows.create({
//         url: "warning.html",
//         type: "popup",
//         width: 400,
//         height: 250
//       });

//       // Close the phishing tab
//       chrome.tabs.remove(details.tabId);
//     }
//   } catch (err) {
//     console.error("Server error:", err);
//   }
// });


// Optional: You can add logging or message relaying if extending functionality in the future.
// chrome.runtime.onMessage.addListener((msg, sender) => {
// Background service worker for the extension (Manifest V3)
// - Intercepts top-level navigations before the page loads
// - Redirects to an in-extension checking page with loader animation
// - Background checks the URL via Flask server and instructs the tab to proceed or show warning UI

const SERVER_URL = "http://127.0.0.1:5000/check_url"; // Flask server

// Simple in-memory cache to reduce redundant checks
// key: normalized URL, value: { verdict: string, ts: number }
const verdictCache = new Map();
const CACHE_TTL_MS = 10 * 60 * 1000; // 10 minutes

// No notification flow; in-page UI will handle proceed/cancel

// One-time proceed bypass: key => `${tabId}|${normalizedUrl}`
const proceedBypass = new Set();
function normalizeUrl(u) {
  try {
    // Lowercase and strip trailing slash in path
    const url = new URL(u);
    url.hash = ""; // ignore fragment
    if (url.pathname.length > 1 && url.pathname.endsWith('/')) {
      url.pathname = url.pathname.slice(0, -1);
    }
    return url.toString();
  } catch (e) {
    return u;
  }
}

// Only handle http/https URLs; ignore chrome://, about:, extension pages, etc.
function isHttpOrHttps(u) {
  try {
    const p = new URL(u).protocol;
    return p === 'http:' || p === 'https:';
  } catch (_) {
    return false;
  }
}

async function getVerdict(url) {
  const key = normalizeUrl(url);
  const now = Date.now();
  const cached = verdictCache.get(key);
  if (cached && (now - cached.ts) < CACHE_TTL_MS) {
    return cached.verdict;
  }
  try {
    const resp = await fetch(SERVER_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();
    const verdict = data && data.verdict ? data.verdict : 'unknown';
    verdictCache.set(key, { verdict, ts: now });
    return verdict;
  } catch (e) {
    console.warn('Server check failed, allowing navigation:', e);
    return 'error';
  }
}

// Intercept navigations using webNavigation (no webRequestBlocking needed)
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  try {
    // Only handle main_frame navigations
    if (details.frameId !== 0 || !details.url) return;

    // Ignore our own extension pages
    const extBase = chrome.runtime.getURL('');
    if (details.url.startsWith(extBase)) return;

    const url = details.url;
    // Ignore non http/https schemes (e.g., chrome://new-tab-page/)
    if (!isHttpOrHttps(url)) return;
    const key = normalizeUrl(url);
    const isRisky = (v) => v === 'phishing' || v === 'malicious' || v === 'suspicious';

    // One-time bypass if user chose Proceed
    const bypassKey = `${details.tabId}|${key}`;
    if (proceedBypass.has(bypassKey)) {
      proceedBypass.delete(bypassKey);
      return; // allow navigation
    }

    // Allow if we have a recent cached safe/unknown/error verdict
    const cached = verdictCache.get(key);
    if (cached && !isRisky(cached.verdict) && (Date.now() - cached.ts) < CACHE_TTL_MS) {
      return; // allow
    }

    // Redirect the tab to our checking UI (this prevents the site from rendering)
    const checkingUrl = chrome.runtime.getURL(`checking.html?target=${encodeURIComponent(url)}`);
    chrome.tabs.update(details.tabId, { url: checkingUrl }, () => {
      if (chrome.runtime.lastError) {
        console.warn('Failed to open checking page:', chrome.runtime.lastError.message);
      }
    });
  } catch (e) {
    console.warn('onBeforeNavigate handler error:', e);
  }
});

// Message handlers for UI pages
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || !sender || !sender.tab) return false;
  const tabId = sender.tab.id;

  if (msg.action === 'checkUrl' && msg.url) {
    (async () => {
      const verdict = await getVerdict(msg.url);
      sendResponse({ verdict });
    })();
    return true; // async response
  }

  if (msg.action === 'proceedToUrl' && msg.url) {
    // Set one-time bypass for this tab+url to avoid interception loop
    const key = normalizeUrl(msg.url);
    proceedBypass.add(`${tabId}|${key}`);
    chrome.tabs.update(tabId, { url: msg.url }, () => {
      if (chrome.runtime.lastError) {
        console.warn('Failed to proceed to URL:', chrome.runtime.lastError.message);
      }
    });
    sendResponse({ ok: true });
    return false;
  }

  if (msg.action === 'closeCurrentTab') {
    chrome.tabs.remove(tabId, () => {
      if (chrome.runtime.lastError) {
        console.warn('Failed to close tab:', chrome.runtime.lastError.message);
      }
    });
    sendResponse({ ok: true });
    return false;
  }

  // Fallback from content script legacy close
  if (msg.action === 'closeTab') {
    chrome.tabs.remove(tabId, () => {
      if (chrome.runtime.lastError) {
        console.warn('Could not close tab:', chrome.runtime.lastError.message);
      }
    });
    sendResponse({ ok: true });
    return false;
  }

  return false;
});
