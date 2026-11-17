"""Extract captioned figures from an RFC text file."""
import re, sys

def clean_lines(path):
    out = []
    for line in open(path, encoding="utf-8"):
        line = line.rstrip("\n").replace("\f", "")
        # drop page header/footer lines
        if re.match(r"^(Miller|Jones|RFC \d{4}|Liusvaara|Josefsson|Schaad|Housley)\b.*(\[Page \d+\]|\d{4})\s*$", line):
            continue
        out.append(line)
    return out

def figures(path):
    """Return {num: (title, body_lines)}; body = indented block right above the caption."""
    lines = clean_lines(path)
    figs = {}
    for i, line in enumerate(lines):
        m = re.match(r"^\s+Figure (\d+): (.*\S)\s*$", line)
        if not m:
            continue
        # walk back over blank lines, then collect the contiguous block,
        # tolerating single blank lines inside (page breaks).
        j = i - 1
        while j >= 0 and not lines[j].strip():
            j -= 1
        body = []
        while j >= 0:
            if not lines[j].strip():
                # stop at a blank line followed (above) by prose (3-space indent, sentence)
                k = j - 1
                while k >= 0 and not lines[k].strip():
                    k -= 1
                if k < 0 or re.match(r"^   [A-Z(]", lines[k]) and not re.match(r"^   [A-Za-z0-9_-]+$", lines[k]):
                    break
                j = k
                continue
            if re.match(r"^\s+Figure \d+:", lines[j]) or re.match(r"^\d", lines[j]):
                break
            body.append(lines[j])
            j -= 1
        figs[int(m.group(1))] = (m.group(2), list(reversed(body)))
    return figs

def b64(body):
    return "".join("".join(body).split())

if __name__ == "__main__":
    for n, (t, b) in sorted(figures(sys.argv[1]).items()):
        print(n, t, "|", len(b))
