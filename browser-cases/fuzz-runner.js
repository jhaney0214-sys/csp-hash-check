// The browser half of fuzz.py. Serve browser-cases/pages/ (the workstation's
// "csp-cases" preview server does), open its index, and run this in the
// page's console. It loads every fuzz page and its policy-free twin in an
// iframe, clicks each javascript: link, reads which marks ran (data-m0..m3
// on <html>, or a #m0..#m3 element 7px wide for style marks), and keeps the
// results in localStorage so a closed tab loses nothing.
//
// When localStorage.fz holds two hex digits a page (low four bits: marks
// that ran under the policy; high four: on the twin), pass that string to
//     python browser-cases/fuzz.py results <string>
//     python browser-cases/fuzz.py compare
//
// Used on 2026-10-18 in Chrome 152 for both rounds (seed 1, and seed 2 with
// --styles), 300 pages each. A hidden preview pane runs it at about one page
// a second.

(async () => {
  const COUNT = 300;
  async function marksOf(src) {
    const f = document.createElement("iframe");
    f.src = src + "?t=" + Date.now();
    await new Promise((r) => { f.onload = r; document.body.appendChild(f); });
    await new Promise((r) => setTimeout(r, 300));       // srcdoc frames load after the page
    const d = f.contentDocument;
    for (const a of d.querySelectorAll("a[id^=j]")) a.click();
    await new Promise((r) => setTimeout(r, 150));
    let bits = 0;
    for (const k of Object.keys(d.documentElement.dataset)) {
      const m = /^m(\d)$/.exec(k);
      if (m) bits |= 1 << +m[1];
    }
    for (let k = 0; k < 4; k++) {
      const el = d.getElementById("m" + k);
      if (el && f.contentWindow.getComputedStyle(el).width === "7px") bits |= 1 << k;
    }
    f.remove();
    return bits;
  }
  let done = localStorage.getItem("fz") || "";
  for (let n = done.length / 2; n < COUNT; n++) {
    const name = "fuzz/f" + String(n).padStart(3, "0");
    const a = await marksOf(name + ".html"), b = await marksOf(name + "-free.html");
    done += (a | (b << 4)).toString(16).padStart(2, "0");
    localStorage.setItem("fz", done);
  }
  console.log("fuzz results:", done);
})();
