// (async () => {
//   const url = window.location.href;

//   try {
//     let response = await fetch("http://127.0.0.1:5000/check_url", {
//       method: "POST",
//       headers: { "Content-Type": "application/json" },
//       body: JSON.stringify({ url })
//     });

//     let data = await response.json();
//     console.log("Server verdict:", data);

//     if (data.verdict === "phishing" || data.verdict === "suspicious" || data.verdict === "malicious") {
//       // Tell background to show warning
//       chrome.runtime.sendMessage({ action: "showWarning", url });
//     }
//   } catch (err) {
//     console.error("Error contacting server:", err);
//   }
// })();


(async () => {
  const url = window.location.href;

  try {
    let response = await fetch("http://127.0.0.1:5000/check_url", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });

    let data = await response.json();
    console.log("Server verdict:", data);

    if (
      data.verdict === "phishing" ||
      data.verdict === "suspicious" ||
      data.verdict === "malicious"
    ) {
      showWarningPopup(url, data.verdict);
    }
    // Don't show anything for legitimate sites!
  } catch (err) {
    console.error("Error contacting server:", err);
    // Optionally notify user if server is down, otherwise silent fail
  }

  // -------- Modal warning logic --------
  function showWarningPopup(url, verdict) {
    if (document.getElementById('phishing-warning-ext')) return;

    const bg = document.createElement('div');
    bg.id = 'phishing-warning-ext';
    bg.style = "position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(200,0,0,.89);color:white;z-index:999999;display:flex;align-items:center;justify-content:center;";

    const box = document.createElement('div');
    box.style = "background:white;color:black;padding:24px 24px 10px 24px;border-radius:8px;text-align:center;max-width:350px;";

    box.innerHTML = `<div style="font-size:19px;font-weight:bold;margin-bottom:8px;">Phishing Warning</div>
      <div style="margin-bottom:14px;">
      The website you are visiting may be <b>${verdict}</b>.<br>
      Are you sure you want to proceed?
      </div>`;

    const btnYes = document.createElement('button');
    btnYes.innerText = "Proceed Anyway";
    btnYes.onclick = () => {
      // Ask background to (re)load this URL explicitly
      try {
        chrome.runtime.sendMessage({ action: 'proceedToUrl', url });
      } catch (e) {
        console.warn('Failed to message background to proceed:', e);
      }
      bg.remove();
    };
    btnYes.style = "background:#ffce2e;color:#222;padding:8px 20px;margin-right:12px;border:none;border-radius:4px;";

    const btnNo = document.createElement('button');
    btnNo.innerText = "Stay Safe (Close Tab)";
    btnNo.onclick = () => {
      // Ask background service worker to close this tab (more reliable than window.close())
      try {
        chrome.runtime.sendMessage({ action: 'closeTab' });
      } catch (e) {
        console.warn('Failed to message background to close tab:', e);
      }
      // Also remove the warning overlay
      bg.remove();
    };
    btnNo.style = "background:#ef3f47;color:white;padding:8px 20px;border:none;border-radius:4px;";

    box.appendChild(btnYes);
    box.appendChild(btnNo);
    bg.appendChild(box);
    document.body.appendChild(bg);
  }
})();
