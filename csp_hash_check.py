"""Check that every inline script a static site ships is allowed by its
Content-Security-Policy, before a browser finds out in production.

    python csp_hash_check.py site/                    # policies from site/_headers and <meta> tags
    python csp_hash_check.py site/ --headers _headers --fail-on-stale

A hash-based policy breaks silently: change one character of an inline
<script> and its sha256 no longer matches the policy, the browser refuses to
run it, and the only error is in the visitor's console. This reads every HTML
file under a directory, hashes each inline script exactly as a browser does,
finds the policy that applies to that page - from a Netlify or Cloudflare Pages
`_headers` file, from a <meta http-equiv> tag, or both, since a browser
enforces every policy it is given - and fails when a script is not allowed.

It also reports what a hash cannot fix: inline event handlers (onclick= and
the rest), which only run under 'unsafe-inline' or 'unsafe-hashes'; and hashes
in a policy that no inline script on its pages produces any more (stale, a
warning unless --fail-on-stale).

With --styles it does the same for inline <style> elements and style=
attributes against style-src. That is off by default: many sites that hash
their scripts still allow inline styles on purpose, and a check that fails
every one of their pages would be switched off.

Standard library only. Output is plain lines, plus GitHub annotations when it
runs inside GitHub Actions.
"""

import argparse
import base64
import hashlib
import os
import re
import sys

SCRIPT = re.compile(r"<script\b([^>]*)>(.*?)</script\s*>", re.S | re.I)
META = re.compile(r"<meta\b[^>]*http-equiv\s*=\s*[\"']?content-security-policy[\"']?[^>]*>", re.I)
CONTENT = re.compile(r"content\s*=\s*(\"([^\"]*)\"|'([^']*)')", re.I)
HANDLER = re.compile(r"<[a-z][^>]*?\s(on[a-z]+)\s*=", re.I)
STYLE = re.compile(r"<style\b([^>]*)>(.*?)</style\s*>", re.S | re.I)
STYLE_ATTR = re.compile(r"<[a-z][^>]*?\sstyle\s*=", re.I)
# Types a browser executes as script. Anything else (JSON-LD, templates,
# importmaps are an exception below) is data and not subject to script-src.
JS_TYPES = {"", "text/javascript", "application/javascript", "module", "text/ecmascript",
            "application/ecmascript", "importmap", "speculationrules"}


def attr(attrs, name):
    m = re.search(r"\b%s\s*=\s*(\"([^\"]*)\"|'([^']*)'|([^\s>]+))" % name, attrs, re.I)
    if not m:
        return None
    return next(g for g in m.groups()[1:] if g is not None)


def parsed(text):
    """Text as the HTML parser hands it on: every CRLF and lone CR become LF
    before a script or style is hashed. A file saved with Windows line endings
    therefore needs the hash of its LF text, not of its bytes (checked in a
    browser 2026-10-18: it refused the CRLF hash and named the LF one)."""
    return text.replace("\r\n", "\n").replace("\r", "\n")


def inline_scripts(html):
    """[(line, source)] for each inline script a browser would run."""
    out = []
    for m in SCRIPT.finditer(html):
        attrs, body = m.group(1), m.group(2)
        if attr(attrs, "src") is not None:
            continue
        kind = (attr(attrs, "type") or "").strip().lower()
        if kind not in JS_TYPES:
            continue
        out.append((html.count("\n", 0, m.start()) + 1, parsed(body)))
    return out


def inline_styles(html):
    """[(line, source)] for each <style> element."""
    return [(html.count("\n", 0, m.start()) + 1, parsed(m.group(2))) for m in STYLE.finditer(html)]


def style_attributes(html):
    """The line of each element carrying a style= attribute."""
    return [html.count("\n", 0, m.start()) + 1 for m in STYLE_ATTR.finditer(html)]


def handlers(html):
    return [(html.count("\n", 0, m.start()) + 1, m.group(1).lower()) for m in HANDLER.finditer(html)]


def digest(source, algorithm="sha256"):
    """The browser's hash: over the UTF-8 bytes of the script text, exactly
    as written, whitespace and line endings included."""
    raw = hashlib.new(algorithm, source.encode("utf-8")).digest()
    return "'%s-%s'" % (algorithm, base64.b64encode(raw).decode())


def digests(source):
    """The source's hash under each algorithm CSP accepts: sha256, sha384, sha512."""
    return {digest(source, a) for a in ("sha256", "sha384", "sha512")}


def normal(source):
    """A hash source with its algorithm lowercased ('SHA384-' is valid CSP); the
    base64 is case-sensitive and kept as written. Other sources are returned as is."""
    algorithm, dash, rest = source.partition("-")
    if dash and algorithm.lower() in ("'sha256", "'sha384", "'sha512"):
        return algorithm.lower() + dash + rest
    return source


def matching(sources, hashed):
    """The sources in a policy that allow a script whose hashes are `hashed`."""
    return {s for s in sources if normal(s) in hashed}


def parse_headers(text):
    """[(pattern, policy)] from a Netlify / Cloudflare Pages _headers file."""
    rules, pattern = [], None
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not raw[:1].isspace():
            pattern = line.strip()
            continue
        name, _, value = line.strip().partition(":")
        if pattern and name.strip().lower() == "content-security-policy":
            rules.append((pattern, value.strip()))
    return rules


def url_paths(rel):
    """The URL paths a file is served at on Netlify and Cloudflare Pages."""
    rel = "/" + rel.replace(os.sep, "/")
    paths = [rel]
    if rel.endswith("/index.html"):
        paths += [rel[: -len("index.html")], rel[: -len("/index.html")] or "/"]
    elif rel.endswith(".html"):
        paths.append(rel[: -len(".html")])
    return paths


def matches(pattern, path):
    """_headers patterns: * (splat) matches anything, :name matches one segment."""
    if pattern.startswith("http"):
        pattern = "/" + pattern.split("/", 3)[-1] if pattern.count("/") >= 3 else "/"
    rx = ""
    for piece in re.split(r"(\*|:[A-Za-z_]+)", pattern):
        if piece == "*":
            rx += ".*"
        elif piece.startswith(":") and len(piece) > 1:
            rx += "[^/]+"
        else:
            rx += re.escape(piece)
    return re.match("^" + rx + "$", path) is not None


def directives(policy):
    out = {}
    for part in policy.split(";"):
        words = part.split()
        if words:
            out.setdefault(words[0].lower(), [w for w in words[1:]])
    return out


def script_sources(policy):
    d = directives(policy)
    for name in ("script-src-elem", "script-src", "default-src"):
        if name in d:
            return name, d[name]
    return None, None


def style_sources(policy):
    d = directives(policy)
    for name in ("style-src-elem", "style-src", "default-src"):
        if name in d:
            return name, d[name]
    return None, None


def allows_style_attributes(policy):
    """style= attributes: 'unsafe-inline' with no hash or nonce beside it, or
    'unsafe-hashes'. A hash alone covers <style> elements, not attributes."""
    d = directives(policy)
    for name in ("style-src-attr", "style-src", "default-src"):
        if name in d:
            s = [x.lower() for x in d[name]]
            if "'unsafe-inline'" in s and not any(x.startswith(("'sha", "'nonce-")) for x in s):
                return True
            return "'unsafe-hashes'" in s
    return True


def allows_inline(sources, hashed):
    """True, False, or 'nonce' when only a nonce could allow it (unchecked).
    `hashed` is one hash source or a set of them (one per algorithm)."""
    lowered = [s.lower() for s in sources]
    if matching(sources, {hashed} if isinstance(hashed, str) else set(hashed)):
        return True
    has_hash_or_nonce = any(s.startswith("'sha") or s.startswith("'nonce-") for s in lowered)
    if "'unsafe-inline'" in lowered and not has_hash_or_nonce:
        return True
    if any(s.startswith("'nonce-") for s in lowered):
        return "nonce"
    return False


def allows_handlers(policy):
    d = directives(policy)
    for name in ("script-src-attr", "script-src", "default-src"):
        if name in d:
            s = [x.lower() for x in d[name]]
            if "'unsafe-inline'" in s and not any(x.startswith(("'sha", "'nonce-")) for x in s):
                return True
            return "'unsafe-hashes'" in s
    return True        # no script policy at all: nothing is blocked


def check(root, headers_file=None, styles=False):
    """(errors, warnings, notes, pages); the first three are lists of
    (file, line, message). With `styles`, inline styles are checked too."""
    errors, warnings, notes = [], [], []
    rules = []
    headers_file = headers_file or os.path.join(root, "_headers")
    if os.path.exists(headers_file):
        with open(headers_file, encoding="utf-8") as fh:
            rules = parse_headers(fh.read())
    used = {i: set() for i in range(len(rules))}
    pages = 0
    for folder, _, files in os.walk(root):
        for name in sorted(files):
            if not name.lower().endswith((".html", ".htm")):
                continue
            path = os.path.join(folder, name)
            rel = os.path.relpath(path, root)
            with open(path, encoding="utf-8", newline="") as fh:
                html = fh.read()
            pages += 1
            policies: list = [(i, p) for i, (pat, p) in enumerate(rules)
                        if any(matches(pat, u) for u in url_paths(rel))]
            for m in META.finditer(html):
                c = CONTENT.search(m.group(0))
                if c:
                    policies.append((None, c.group(2) if c.group(2) is not None else c.group(3)))
            scripts = inline_scripts(html)
            if not policies:
                if scripts:
                    notes.append((rel, 1, "no Content-Security-Policy applies; %d inline script(s) unchecked" % len(scripts)))
                continue
            for line, source in scripts:
                h, every = digest(source), digests(source)
                for i, policy in policies:
                    name, sources = script_sources(policy)
                    if sources is None:
                        continue
                    verdict = allows_inline(sources, every)
                    if verdict is True and i is not None:
                        used[i].update(matching(sources, every))
                    if verdict is False:
                        where = "_headers" if i is not None else "<meta> policy"
                        errors.append((rel, line, "inline script blocked by %s (%s): add %s" % (where, name, h)))
                    elif verdict == "nonce":
                        notes.append((rel, line, "inline script relies on a nonce, which a static check cannot verify"))
            if styles:
                for line, source in inline_styles(html):
                    h, every = digest(source), digests(source)
                    for i, policy in policies:
                        name, sources = style_sources(policy)
                        if sources is None:
                            continue
                        verdict = allows_inline(sources, every)
                        if verdict is True and i is not None:
                            used[i].update(matching(sources, every))
                        if verdict is False:
                            where = "_headers" if i is not None else "<meta> policy"
                            errors.append((rel, line, "inline style blocked by %s (%s): add %s"
                                           % (where, name, h)))
                        elif verdict == "nonce":
                            notes.append((rel, line, "inline style relies on a nonce, which a static "
                                                     "check cannot verify"))
                for line in style_attributes(html):
                    if not all(allows_style_attributes(p) for _, p in policies):
                        errors.append((rel, line, "style= attribute is blocked: move it into a "
                                                  "stylesheet, or allow it with 'unsafe-hashes'"))
            for line, attr_name in handlers(html):
                if not all(allows_handlers(p) for _, p in policies):
                    errors.append((rel, line, "inline %s= handler is blocked: move it into a script file, "
                                              "or allow it with 'unsafe-hashes'" % attr_name))
    for i, (pattern, policy) in enumerate(rules):
        _, sources = script_sources(policy)
        for s in sources or []:
            if s.lower().startswith("'sha") and s not in used[i]:
                warnings.append((os.path.relpath(headers_file, root), 1,
                                 "%s under %s matches no inline script: stale?" % (s, pattern)))
        if styles:
            name, style = style_sources(policy)
            # default-src is shared with scripts and was reported just above.
            for s in (style or []) if name != "default-src" else []:
                if s.lower().startswith("'sha") and s not in used[i]:
                    warnings.append((os.path.relpath(headers_file, root), 1,
                                     "%s under %s matches no inline style: stale?" % (s, pattern)))
    return errors, warnings, notes, pages


def main(argv=None):
    ap = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    ap.add_argument("root", help="the directory the site is served from")
    ap.add_argument("--headers", help="a _headers file (default: <root>/_headers)")
    ap.add_argument("--fail-on-stale", action="store_true", help="treat unused hashes as errors")
    ap.add_argument("--styles", action="store_true",
                    help="also check inline <style> elements and style= attributes against style-src")
    a = ap.parse_args(argv)
    errors, warnings, notes, pages = check(a.root, a.headers, styles=a.styles)
    if a.fail_on_stale:
        errors, warnings = errors + warnings, []
    gh = os.environ.get("GITHUB_ACTIONS") == "true"
    for kind, items in (("error", errors), ("warning", warnings), ("notice", notes)):
        for f, line, msg in items:
            print(("::%s file=%s,line=%d::%s" % (kind, os.path.join(a.root, f), line, msg)) if gh
                  else "%-7s %s:%d  %s" % (kind, f, line, msg))
    print("%d page(s) checked: %d error(s), %d warning(s)" % (pages, len(errors), len(warnings)))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
