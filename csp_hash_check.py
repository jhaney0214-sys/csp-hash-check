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

It also checks what a script hash cannot allow: inline event handlers
(onclick= and the rest) and javascript: links, which run only under
'unsafe-inline' or under 'unsafe-hashes' with their own hash listed; and it
reports hashes in a policy that nothing on its pages produces any more (stale,
a warning unless --fail-on-stale).

With --styles it does the same for inline <style> elements and style=
attributes against style-src. That is off by default: many sites that hash
their scripts still allow inline styles on purpose, and a check that fails
every one of their pages would be switched off.

The rules are the browser's, and browser-cases/ holds the pages they were
checked on: a script in a comment or a <noscript> never runs, a <meta> policy
governs only what follows it inside <head>, 'strict-dynamic' switches
'unsafe-inline' off. test_browser_cases.py holds this file to what the
browser did.

Standard library only. Output is plain lines, plus GitHub annotations when it
runs inside GitHub Actions.
"""

import argparse
import base64
import hashlib
import os
import re
import sys
from html.parser import HTMLParser

# The HTML standard's JavaScript MIME type essences, plus the other types a
# browser runs as script. A type with parameters ("text/javascript;
# charset=utf-8") is not an essence match and does not run (browser-cases).
JS_TYPES = {"", "module", "importmap", "speculationrules",
            "application/ecmascript", "application/javascript", "application/x-ecmascript",
            "application/x-javascript", "text/ecmascript", "text/javascript", "text/javascript1.0",
            "text/javascript1.1", "text/javascript1.2", "text/javascript1.3", "text/javascript1.4",
            "text/javascript1.5", "text/jscript", "text/livescript", "text/x-ecmascript",
            "text/x-javascript"}
# Elements whose content a browser never parses as markup when scripting is
# on: anything inside them, a <script> included, is text.
RAW_TEXT = {"noscript", "textarea", "title", "xmp", "iframe", "noembed", "noframes", "plaintext"}
# What may sit in <head>; the first other element starts <body>, and a <meta>
# policy after that point is ignored.
HEAD_TAGS = {"html", "head", "meta", "title", "link", "style", "script", "base", "noscript", "template"}
# Attributes whose javascript: URL runs as script when followed.
URL_ATTRS = {("a", "href"), ("area", "href"), ("iframe", "src"), ("frame", "src"),
             ("form", "action"), ("button", "formaction"), ("input", "formaction")}
HASH_PREFIXES = ("'sha256-", "'sha384-", "'sha512-")
SCRIPT_COUNT = re.compile(r"<script\b(?![^>]*\bsrc\s*=)[^>]*>", re.I)


def parsed(text):
    """Text as the HTML parser hands it on: every CRLF and lone CR become LF
    before a script or style is hashed. A file saved with Windows line endings
    therefore needs the hash of its LF text, not of its bytes (checked in a
    browser 2026-10-18: it refused the CRLF hash and named the LF one)."""
    return text.replace("\r\n", "\n").replace("\r", "\n")


def script_type(attrs):
    """The type a browser decides a <script> has, lowercased and trimmed."""
    if "type" in attrs:
        return (attrs["type"] or "").strip().lower()
    if attrs.get("language"):
        return "text/" + attrs["language"].strip().lower()
    return ""


class Page(HTMLParser):
    """Everything inline on one page that a policy can block, with its position.

    items: dicts with kind (script, style, handler, style-attr, url), line,
    pos ((line, column), for ordering against <meta> policies), text (what
    is hashed) and name (the attribute, for handlers and URLs).
    metas: (pos, policy) for each <meta> policy a browser enforces.
    ignored: (line, why) for each <meta> policy a browser ignores.
    """

    def __init__(self, html):
        HTMLParser.__init__(self, convert_charrefs=True)
        self.html = html
        self.starts = [0] + [m.end() for m in re.finditer("\n", html)]
        self.items, self.metas, self.ignored = [], [], []
        self.in_head = True
        self.raw = 0              # depth inside RAW_TEXT elements
        self.open = None          # (kind, pos, attrs, body start) of an open <script> or <style>
        self.feed(html)
        self.close()

    def _offset(self, pos):
        return self.starts[pos[0] - 1] + pos[1]

    def _add(self, kind, pos, text, name=None):
        self.items.append({"kind": kind, "line": pos[0], "pos": pos, "text": text, "name": name})

    def handle_starttag(self, tag, attr_list):
        pos = self.getpos()
        if self.raw:
            if tag in RAW_TEXT:
                self.raw += 1
            return
        if tag == "body" or tag not in HEAD_TAGS:
            self.in_head = False
        attrs = {}
        for name, value in attr_list:
            attrs.setdefault(name, value)        # the first of a repeated attribute wins
        for name, value in attrs.items():
            if name.startswith("on") and len(name) > 2:
                self._add("handler", pos, value or "", name)
            elif name == "style" and value is not None:
                self._add("style-attr", pos, value, name)
            elif (tag, name) in URL_ATTRS and value and value.strip().lower().startswith("javascript:"):
                self._add("url", pos, value.strip(), name)
        if tag == "meta":
            equiv = (attrs.get("http-equiv") or "").strip().lower()
            if equiv == "content-security-policy" and attrs.get("content") is not None:
                if self.in_head:
                    self.metas.append((pos, attrs["content"]))
                else:
                    self.ignored.append((pos[0], "a <meta> policy outside <head> is ignored by browsers"))
        if tag in ("script", "style"):
            start = self._offset(pos) + len(self.get_starttag_text() or "")
            self.open = (tag, pos, attrs, start)
        if tag in RAW_TEXT:
            self.raw = 1

    def handle_startendtag(self, tag, attrs):
        if tag in ("script", "style"):
            return                     # <script/> is a start tag in HTML; its body follows
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        if self.raw:
            if tag in RAW_TEXT:
                self.raw -= 1
            return
        if tag == "head":
            self.in_head = False
        if self.open and tag == self.open[0]:
            kind, pos, attrs, start = self.open
            self.open = None
            body = parsed(self.html[start:self._offset(self.getpos())])
            if kind == "style":
                self._add("style", pos, body)
            elif attrs.get("src") is None and script_type(attrs) in JS_TYPES:
                self._add("script", pos, body)


def inline_scripts(html):
    """[(line, source)] for each inline script a browser would run."""
    return [(i["line"], i["text"]) for i in Page(html).items if i["kind"] == "script"]


def digest(source, algorithm="sha256"):
    """The browser's hash: over the UTF-8 bytes of the text as parsed."""
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
    """The sources in a policy that allow code whose hashes are `hashed`."""
    return {s for s in sources if normal(s) in hashed}


def is_hash(source):
    return source.lower().startswith(HASH_PREFIXES)


def parse_headers(text):
    """[(pattern, policy, line)] from a Netlify / Cloudflare Pages _headers file."""
    rules, pattern = [], None
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not raw[:1].isspace():
            pattern = line.strip()
            continue
        name, _, value = line.strip().partition(":")
        if pattern and name.strip().lower() == "content-security-policy":
            rules.append((pattern, value.strip(), number))
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


# Which directive governs each kind of inline code, most specific first. A
# javascript: URL is checked as a navigation, which uses script-src-elem.
CHAINS = {
    "script": ("script-src-elem", "script-src", "default-src"),
    "url": ("script-src-elem", "script-src", "default-src"),
    "handler": ("script-src-attr", "script-src", "default-src"),
    "style": ("style-src-elem", "style-src", "default-src"),
    "style-attr": ("style-src-attr", "style-src", "default-src"),
}
ELEMENTS = {"script", "style"}          # what a hash or a nonce allows directly


def governing(policy, kind):
    """(directive name, sources) that govern `kind` under `policy`, or (None, None)."""
    d = directives(policy) if isinstance(policy, str) else policy
    for name in CHAINS[kind]:
        if name in d:
            return name, d[name]
    return None, None


def script_sources(policy):
    return governing(policy, "script")


def style_sources(policy):
    return governing(policy, "style")


def judge(sources, kind, every):
    """True (allowed), False (blocked), or 'nonce' (only a nonce could allow it,
    which a static file cannot show). `every` is the code's set of hashes.

    - A hash allows a <script> or <style> element directly.
    - A handler, a style= attribute or a javascript: URL needs 'unsafe-hashes'
      beside its hash (browser-cases: unsafe-hashes-*, javascript-url-*).
    - 'unsafe-inline' allows all of them, unless a hash or a nonce is listed,
      or, for script, 'strict-dynamic' (browser-cases: strict-dynamic-*).
    """
    lowered = [s.lower() for s in sources]
    hashed = matching(sources, every)
    if hashed and (kind in ELEMENTS or "'unsafe-hashes'" in lowered):
        return True
    has_hash_or_nonce = any(is_hash(s) or s.startswith("'nonce-") for s in lowered)
    dynamic = kind in ("script", "handler", "url") and "'strict-dynamic'" in lowered
    if "'unsafe-inline'" in lowered and not has_hash_or_nonce and not dynamic:
        return True
    if kind in ELEMENTS and any(s.startswith("'nonce-") for s in lowered):
        return "nonce"
    return False


def allows_inline(sources, hashed):
    """The script element rule alone; kept for callers of the 1.x API."""
    return judge(sources, "script", {hashed} if isinstance(hashed, str) else set(hashed))


def blocked_message(item, where, directive, h):
    kind = item["kind"]
    if kind == "script":
        return "inline script blocked by %s (%s): add %s" % (where, directive, h)
    if kind == "style":
        return "inline style blocked by %s (%s): add %s" % (where, directive, h)
    if kind == "handler":
        return ("inline %s= handler is blocked by %s (%s): move it into a script file, "
                "or allow it with 'unsafe-hashes' and %s" % (item["name"], where, directive, h))
    if kind == "style-attr":
        return ("style= attribute is blocked by %s (%s): move it into a stylesheet, "
                "or allow it with 'unsafe-hashes' and %s" % (where, directive, h))
    return ("javascript: URL in %s= is blocked by %s (%s): use a click handler in a script file, "
            "or allow it with 'unsafe-hashes' and %s" % (item["name"], where, directive, h))


def read_page(path):
    with open(path, encoding="utf-8", newline="") as fh:
        return fh.read()


def check(root, headers_file=None, styles=False):
    """(errors, warnings, notes, pages); the first three are lists of
    (file, line, message). With `styles`, inline styles are checked too."""
    errors, warnings, notes = [], [], []
    rules = []
    headers_file = headers_file or os.path.join(root, "_headers")
    if os.path.exists(headers_file):
        with open(headers_file, encoding="utf-8") as fh:
            rules = parse_headers(fh.read())
    parsed_rules = [directives(p) for _, p, _ in rules]
    used = {i: set() for i in range(len(rules))}
    kinds = {"script", "handler", "url"} | ({"style", "style-attr"} if styles else set())
    pages = 0
    for folder, subfolders, files in os.walk(root):
        subfolders.sort()
        for name in sorted(files):
            if not name.lower().endswith((".html", ".htm")):
                continue
            path = os.path.join(folder, name)
            rel = os.path.relpath(path, root)
            html = read_page(path)
            pages += 1
            applying = [i for i, (pat, _, _) in enumerate(rules)
                        if any(matches(pat, u) for u in url_paths(rel))]
            if not applying and "content-security-policy" not in html.lower():
                scripts = len(SCRIPT_COUNT.findall(html))
                if scripts:
                    notes.append((rel, 1, "no Content-Security-Policy applies; %d inline script(s) unchecked"
                                  % scripts))
                continue
            page = Page(html)
            for line, why in page.ignored:
                notes.append((rel, line, why))
            if not applying and not page.metas:
                scripts = sum(1 for i in page.items if i["kind"] == "script")
                if scripts:
                    notes.append((rel, 1, "no Content-Security-Policy applies; %d inline script(s) unchecked"
                                  % scripts))
                continue
            for item in page.items:
                if item["kind"] not in kinds:
                    continue
                # Header policies govern the whole page; a <meta> policy only
                # what the parser reaches after it.
                policies = [(i, parsed_rules[i]) for i in applying] + \
                           [(None, directives(p)) for pos, p in page.metas if pos < item["pos"]]
                every, h = digests(item["text"]), digest(item["text"])
                for i, policy in policies:
                    directive, sources = governing(policy, item["kind"])
                    if sources is None:
                        continue
                    verdict = judge(sources, item["kind"], every)
                    if verdict is True:
                        if i is not None:
                            used[i].update(matching(sources, every))
                        continue
                    if verdict == "nonce":
                        notes.append((rel, item["line"], "inline %s relies on a nonce, which a static check "
                                                         "cannot verify" % item["kind"]))
                        continue
                    where = "_headers" if i is not None else "<meta> policy"
                    errors.append((rel, item["line"], blocked_message(item, where, directive, h)))
                    break                       # one error for each piece of code, naming a policy
    hfile = os.path.relpath(headers_file, root)
    for i, (pattern, _, line) in enumerate(rules):
        d = parsed_rules[i]
        script_dirs = [n for n in ("script-src-elem", "script-src", "script-src-attr") if n in d]
        style_dirs = [n for n in ("style-src-elem", "style-src", "style-src-attr") if n in d]
        checks = [("script", script_dirs or (["default-src"] if "default-src" in d else []))]
        if styles:
            # default-src is shared with scripts, and was reported with them.
            checks.append(("style", style_dirs))
        reported = set()
        for what, names in checks:
            for directive in names:
                for s in d[directive]:
                    if is_hash(s) and s not in used[i] and s not in reported:
                        reported.add(s)
                        warnings.append((hfile, line, "%s under %s matches no inline %s: stale?"
                                         % (s, pattern, what)))
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
