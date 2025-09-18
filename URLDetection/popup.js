// document.getElementById("yes").addEventListener("click", async () => {
//   let { blockedUrl } = await chrome.storage.local.get("blockedUrl");
//   if (blockedUrl) {
//     chrome.tabs.create({ url: blockedUrl });
//     chrome.storage.local.remove("blockedUrl");
//     window.close();
//   }
// });

// document.getElementById("no").addEventListener("click", () => {
//   chrome.storage.local.remove("blockedUrl");
//   window.close(); // just close popup, URL stays blocked
// });
// not required
