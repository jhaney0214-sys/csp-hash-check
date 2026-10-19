# CSP Hash Check

[On the GitHub Marketplace](https://github.com/marketplace/actions/csp-hash-check)

Fail the build when an inline script on your static site is not allowed by its
Content-Security-Policy.

A hash-based policy breaks silently. Change one character of an inline
`<script>` and its sha256 no longer matches the hash in your policy: the
browser refuses to run it, the page stops working, and the only error is in
the visitor's console. Nothing in your build notices. This does.

It reads every HTML file under a directory, hashes each inline script the way a
browser does, finds the policy that applies to that page, and fails when a
script is not allowed, naming the hash to add:

```
error   index.html:91  inline script blocked by _headers (script-src): add 'sha256-Xxa4L/fnpwlQ+ulhuHg4j6bHqwI2Pgwy04CLwyk+HSc='
warning _headers:1  'sha256-q45lW+RZ+SStMbA0LFEjvaSHTrShlCQhrgv1E12Wrxc=' under /* matches no inline script: stale?
1 page(s) checked: 1 error(s), 1 warning(s)
```

## Use

```yaml
- uses: actions/checkout@v4
- uses: jhaney0214-sys/csp-hash-check@v1
  with:
    path: public            # the directory your site is served from
```

| Input | Default | |
|---|---|---|
| `path` | required | The directory the site is served from |
| `headers` | `<path>/_headers` | A `_headers` file kept somewhere else |
| `fail-on-stale` | `false` | Treat hashes no inline script uses any more as errors |
| `styles` | `false` | Also check inline styles against `style-src` (since `v1.1.0`; see below) |
| `config` | found | A `netlify.toml`, `vercel.json` or `firebase.json` elsewhere than the site directory or the repository root, where each is found on its own. Since `v1.2.0` |
| `exclude` | none | Pages to skip, one glob per line; a bare name skips every folder of that name (`drafts`). Since `v1.2.0` |
| `json` | none | Also write every finding to this file as JSON (`pages`, `passed`, `findings` with level, file, line, message). Since `v1.2.0` |
| `python-version` | `3.x` | Any 3.9 or later. Used by the action only: since `v1.2.1` it stays off the job's `PATH`, so your later steps keep the Python you set up (before, they ran on this one) |

Or run it anywhere Python is: `python csp_hash_check.py public/`. It has no
dependencies.

Writing a policy, or updating one after an edit:

```
python csp_hash_check.py public/ --suggest
```

lists the hash each page's inline code needs, then one `script-src` line
(and with `--styles`, a `style-src` line) that allows all of them, with
`'unsafe-hashes'` added only when a handler, `style=` attribute or
`javascript:` link needs it. It checks nothing. Since `v1.2.0`.

## What it checks

- **Every inline script** (`<script>` with no `src`, including `type="module"`
  and the older JavaScript types such as `text/jscript`) against every policy
  that applies to its page. What a browser never runs is skipped: data
  blocks such as JSON-LD, a type with parameters, and anything inside an HTML
  comment or a `<noscript>`. Markup written inside a script's strings is not
  mistaken for handlers. The page is read with an HTML parser, not patterns.
- **Policies from where static hosts keep them:** a Netlify or Cloudflare
  Pages `_headers` file, with its `*` and `:placeholder` path patterns matched
  against the URL each file is served at (`/about.html`, `/about`, `/docs/`);
  `netlify.toml` (`[[headers]]`, needs Python 3.11 for `tomllib`);
  `vercel.json` (`headers`, with `/:path*`-style sources); `firebase.json`
  (`hosting.headers`, with `**` and `@(a|b)` globs); and
  `<meta http-equiv="Content-Security-Policy">` tags. The three config files
  are found in the site directory or the directory the check runs from; a
  rule's `has` or `missing` conditions (Vercel) are not evaluated. A browser enforces every
  policy it is given, so a script has to pass all of them. A `<meta>` policy
  governs only what follows it, and only inside `<head>`; one in the body, or
  marked report-only, is ignored, as browsers ignore it. A comma separates
  two policies in one value, and both are enforced. Cloudflare Pages'
  `! Content-Security-Policy` under a path takes the header off there.
- **Line endings as the browser reads them.** The HTML parser turns CRLF
  into LF before a script is hashed, so a page saved with Windows line
  endings is hashed on its LF text. (Since `v1.1.0`, after a browser refused
  the CRLF hash; `v1.0.0` hashed the bytes, so on a CRLF page it reported
  every script blocked and suggested a hash the browser rejects.)
- **The page's own encoding.** A browser hashes the UTF-8 encoding of the
  text it decoded, so a windows-1252 page is decoded first: by its
  byte-order mark, its `<meta charset>` (latin-1 read as windows-1252, as
  browsers do), as UTF-8 if it is valid, and otherwise as windows-1252 with a
  note saying so. Before `v1.2.0` a page that was not UTF-8 stopped the run.
- **Hashes in any of CSP's three algorithms:** `sha256`, `sha384` and
  `sha512`, with the algorithm name in any case. (Since `v1.1.0`;
  `v1.0.0` knew only `sha256` and failed a `sha384` policy on every page.) A
  missing hash is always suggested as `sha256`.
- **The browser's rules for falling back:** `script-src-elem`, then
  `script-src`, then `default-src`; `'unsafe-inline'` ignored once a hash or
  nonce is listed, and for scripts once `'strict-dynamic'` is.
- **Inline event handlers** (`onclick=`, `onsubmit=` and the rest) and
  **`javascript:` links**, which no script hash allows. They run under
  `'unsafe-inline'`, or under `'unsafe-hashes'` with their own hash listed;
  the error names that hash.
- **Where a script really ends.** An old-style script wrapped in `<!-- -->`
  that holds `"<script></script>"` in a string runs on past that inner tag,
  and a script inside `<svg>` drops its `<![CDATA[` markers and decodes
  `&lt;` before it is hashed. Both follow the HTML standard's tokenizer, and
  both are browser cases.
- **`<iframe srcdoc>` documents**, which inherit the page's policy, so their
  scripts and handlers need hashes in it. Errors from them say so.
- **Only real event handlers.** An attribute that merely starts with `on`
  (`onboarding=`) is not a handler; it is noted, so a name the checker does
  not know is said aloud rather than passed in silence.
- **Scripts in `<template>`** run only if a script clones them into the page,
  so a blocked one is a notice naming the hash it would need, not an error.
- **Checked against a browser.** `browser-cases/` holds a page for each of
  these rules and `observed.json` what Chrome did with it;
  `test_browser_cases.py` fails if the checker ever disagrees. `browser-cases/fuzz.py` goes further:
  it writes random pages mixing all of the above under random policies, each
  with a twin that has no policy, and compares what Chrome ran with what the
  checker reports. Its first 300 pages found two disagreements, both fixed
  and both now cases; the 300 then agreed. A second round (`--styles`: inline
  styles, `srcdoc`, nonces, duplicate attributes, more) found one more: a
  script inside SVG `<foreignObject>` or MathML `<mtext>` is HTML again, and
  was hashed as SVG (27 of 300 pages). Fixed; both rounds, 600 pages, now
  agree with Chrome. Since `v1.2.0`,
  which fixed four ways it disagreed: `'unsafe-hashes'` passed every handler,
  `'strict-dynamic'` did not switch `'unsafe-inline'` off, a `<meta>` policy
  governed the whole page, and scripts in comments and `<noscript>` were
  checked.
- **Stale hashes:** hashes in a `_headers` policy that nothing on its pages
  produces, reported at the policy's line. A warning, or an error with
  `fail-on-stale`.

## What it does not check

- **Scripts added at run time** by other scripts. It reads the HTML you ship.
- **Nonces minted by a server.** A policy this reads is written in a file,
  so its nonce is the same on every response: a script without that nonce
  is reported blocked, and one with it is a warning, since a nonce that
  never changes protects nothing (the warning names the hash to use
  instead). A site whose server mints a nonce per response and sets the
  header itself is outside what a static check can see.
- **Inline styles, unless you ask.** `styles: true` (or `--styles`) checks
  `<style>` elements against `style-src-elem`, `style-src`, then
  `default-src`, and `style=` attributes against `style-src-attr` and the
  same fallbacks; a hash covers an element and never an attribute. It is off
  by default because many sites that hash their scripts allow inline styles
  on purpose. Since `v1.1.0`. Styles set from script (`element.style`) are not seen.
- **Headers set elsewhere**, by a server, CDN rule or framework config. It
  reads `_headers` and `<meta>` only.
- **Whether the policy is a good one.** It checks that your scripts fit the
  policy you wrote, not that the policy is strict enough.

## Why it exists

It was written after doing this check by hand on two live sites: one inline
script allowed by its hash, and one `onsubmit=` attribute that a new policy
would have blocked. Getting either wrong produces no build error.

## Licence

MIT. See `LICENSE`.
