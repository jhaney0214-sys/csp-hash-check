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
| `styles` | `false` | Also check inline styles against `style-src` (not in `v1.0.0`; see below) |
| `python-version` | `3.x` | Any 3.8 or later |

Or run it anywhere Python is: `python csp_hash_check.py public/`. It has no
dependencies.

## What it checks

- **Every inline script** (`<script>` with no `src`, including `type="module"`)
  against every policy that applies to its page. Data blocks a browser does
  not run, such as JSON-LD and templates, are skipped.
- **Policies from two places:** a Netlify or Cloudflare Pages `_headers` file,
  with its `*` and `:placeholder` path patterns matched against the URL each
  file is served at (`/about.html`, `/about`, `/docs/`), and
  `<meta http-equiv="Content-Security-Policy">` tags. A browser enforces every
  policy it is given, so a script has to pass all of them.
- **Line endings as the browser reads them.** The HTML parser turns CRLF
  into LF before a script is hashed, so a page saved with Windows line
  endings is hashed on its LF text. (On `main` since 2026-10-18, after a
  browser refused the CRLF hash; `v1` hashes the bytes, so on a CRLF page it
  reports every script blocked and suggests a hash the browser rejects.)
- **Hashes in any of CSP's three algorithms:** `sha256`, `sha384` and
  `sha512`, with the algorithm name in any case. (On `main` since
  2026-10-18; `v1` knows only `sha256`, and fails a `sha384` policy on every
  page.) A missing hash is always suggested as `sha256`.
- **The browser's rules for falling back:** `script-src-elem`, then
  `script-src`, then `default-src`; `'unsafe-inline'` ignored once a hash or
  nonce is listed.
- **Inline event handlers** (`onclick=`, `onsubmit=` and the rest), which no
  script hash allows. They run only under `'unsafe-inline'` or
  `'unsafe-hashes'`.
- **Stale hashes:** hashes in a `_headers` policy that no inline script on its
  pages produces. A warning, or an error with `fail-on-stale`.

## What it does not check

- **Scripts added at run time** by other scripts. It reads the HTML you ship.
- **Nonces.** A nonce is minted per response, so a static file cannot be
  checked against one; pages that rely on one are noted, not judged.
- **Inline styles, unless you ask.** `styles: true` (or `--styles`) checks
  `<style>` elements against `style-src-elem`, `style-src`, then
  `default-src`, and `style=` attributes against `style-src-attr` and the
  same fallbacks; a hash covers an element and never an attribute. It is off
  by default because many sites that hash their scripts allow inline styles
  on purpose. Added 2026-10-13 on `main`; the `v1` tag does not have it until
  a release moves it. Styles set from script (`element.style`) are not seen.
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
