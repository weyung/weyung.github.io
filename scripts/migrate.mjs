#!/usr/bin/env node

import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { basename, dirname, extname, join, relative } from "node:path";

const SOURCE_DIR = "D:/Personal/blog/source/_posts";
const TARGET_DIR = "posts";

function slugify(input) {
  return String(input || "")
    .trim()
    .toLowerCase()
    .replace(/\s+/g, "-")
    .replace(/[^\p{L}\p{N}\-_.~]/gu, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "");
}

function walkMd(dir) {
  const results = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push(...walkMd(full));
    } else if (extname(entry.name).toLowerCase() === ".md") {
      results.push(full);
    }
  }
  return results;
}

function parseFrontmatter(content) {
  const match = content.match(/^---\r?\n([\s\S]*?)\r?\n---/);
  if (!match) return null;

  const yaml = match[1];
  const body = content.slice(match[0].length).replace(/^\r?\n/, "");
  const fields = {};

  for (const line of yaml.split(/\r?\n/)) {
    const m = line.match(/^(\w+):\s*(.*)/);
    if (m) fields[m[1]] = m[2].trim();
  }

  let tags = [];
  const rawTags = fields.tags || "";
  if (rawTags.startsWith("[")) {
    tags = rawTags.slice(1, -1).split(",").map((t) => t.trim()).filter(Boolean);
  } else if (rawTags) {
    tags = [rawTags.trim()];
  }

  const dateMatch = (fields.date || "").match(/(\d{4})-(\d{2})-(\d{2})[\sT](\d{2}):(\d{2}):(\d{2})/);
  const date = dateMatch
    ? { year: +dateMatch[1], month: +dateMatch[2], day: +dateMatch[3], hour: +dateMatch[4], minute: +dateMatch[5], second: +dateMatch[6] }
    : null;

  return {
    title: fields.title || "",
    date,
    tags,
    category: fields.categories || "",
    body,
  };
}

function extractDescription(body) {
  const moreIdx = body.indexOf("<!--more-->");
  if (moreIdx === -1) return { description: "", content: body };
  const before = body.slice(0, moreIdx).trim();
  const after = body.slice(moreIdx + "<!--more-->".length).replace(/^\r?\n/, "");
  return { description: before, content: after };
}

function escapeTypstString(s) {
  return s.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

function hasMath(text) {
  return /\$\$[\s\S]+?\$\$|\$[^\$\n]+?\$|\\frac|\\sum|\\int|\\alpha|\\begin\{/.test(text);
}

// LaTeX math → Typst math conversion
function convertLatexMath(math) {
  let s = math;

  // \text{...} / \mathrm{...} / \textbf{...} → "..."
  s = s.replace(/\\(?:text|mathrm|textbf|textrm|operatorname)\{([^}]*)\}/g, '"$1"');
  // \mathrm X (no braces, single char) → "X"
  s = s.replace(/\\(?:text|mathrm|textrm)\s([a-zA-Z])/g, '"$1"');

  // \frac{a}{b} → frac(a, b)
  s = s.replace(/\\frac\{([^}]*)\}\{([^}]*)\}/g, "frac($1, $2)");

  // \sqrt[n]{x} → root(n, x)
  s = s.replace(/\\sqrt\[([^\]]*)\]\{([^}]*)\}/g, "root($1, $2)");
  // \sqrt{x} → sqrt(x)
  s = s.replace(/\\sqrt\{([^}]*)\}/g, "sqrt($1)");

  // \hat{x}, \bar{x}, \vec{x}, \tilde{x}, \dot{x}, \ddot{x}
  s = s.replace(/\\hat\{([^}]*)\}/g, "hat($1)");
  s = s.replace(/\\bar\{([^}]*)\}/g, "macron($1)");
  s = s.replace(/\\overline\{([^}]*)\}/g, "overline($1)");
  s = s.replace(/\\vec\{([^}]*)\}/g, "arrow($1)");
  s = s.replace(/\\tilde\{([^}]*)\}/g, "tilde($1)");
  s = s.replace(/\\dot\{([^}]*)\}/g, "dot($1)");
  s = s.replace(/\\ddot\{([^}]*)\}/g, "dot.double($1)");
  s = s.replace(/\\mathbb\{([^}]*)\}/g, "bb($1)");
  s = s.replace(/\\mathcal\{([^}]*)\}/g, "cal($1)");
  s = s.replace(/\\binom\{([^}]*)\}\{([^}]*)\}/g, "binom($1, $2)");

  // \pmod{n} → mod n, \bmod → mod
  s = s.replace(/\\pmod\{([^}]*)\}/g, "mod $1");
  s = s.replace(/\\bmod/g, "mod");
  s = s.replace(/\\mod/g, "mod");

  // \left / \right delimiters → just the delimiter
  s = s.replace(/\\left\s*/g, "");
  s = s.replace(/\\right\s*/g, "");
  s = s.replace(/\\big\s*/g, "");
  s = s.replace(/\\Big\s*/g, "");
  s = s.replace(/\\bigg\s*/g, "");
  s = s.replace(/\\Bigg\s*/g, "");

  // _{...} → _(...)  and ^{...} → ^(...)
  s = s.replace(/\_\{([^}]*)\}/g, "_($1)");
  s = s.replace(/\^\{([^}]*)\}/g, "^($1)");

  // \{ \} → { }  (escaped braces)
  s = s.replace(/\\\{/g, "{");
  s = s.replace(/\\\}/g, "}");

  // Remaining {...} groups that aren't function args → just strip braces
  // (e.g., {x+y} → x+y)
  s = s.replace(/\{([^}]*)\}/g, "$1");

  // Greek letters
  const greekMap = {
    alpha: "alpha", beta: "beta", gamma: "gamma", delta: "delta",
    epsilon: "epsilon", varepsilon: "epsilon.alt", zeta: "zeta",
    eta: "eta", theta: "theta", vartheta: "theta.alt",
    iota: "iota", kappa: "kappa", lambda: "lambda", mu: "mu",
    nu: "nu", xi: "xi", pi: "pi", rho: "rho",
    sigma: "sigma", tau: "tau", upsilon: "upsilon",
    phi: "phi", varphi: "phi.alt", chi: "chi", psi: "psi", omega: "omega",
    Gamma: "Gamma", Delta: "Delta", Theta: "Theta", Lambda: "Lambda",
    Xi: "Xi", Pi: "Pi", Sigma: "Sigma", Phi: "Phi", Psi: "Psi", Omega: "Omega",
  };
  for (const [latex, typst] of Object.entries(greekMap)) {
    s = s.replace(new RegExp(`\\\\${latex}(?![a-zA-Z])`, "g"), typst + " ");
  }

  // Common operators and symbols
  const symbolMap = {
    "\\infty": "infinity", "\\partial": "diff", "\\nabla": "nabla",
    "\\forall": "forall", "\\exists": "exists",
    "\\sum": "sum", "\\prod": "product", "\\int": "integral",
    "\\iint": "integral.double", "\\iiint": "integral.triple",
    "\\oint": "integral.cont",
    "\\lim": "lim", "\\sup": "sup", "\\inf": "inf",
    "\\min": "min", "\\max": "max",
    "\\sin": "sin", "\\cos": "cos", "\\tan": "tan",
    "\\cot": "cot", "\\sec": "sec", "\\csc": "csc",
    "\\arcsin": "arcsin", "\\arccos": "arccos", "\\arctan": "arctan",
    "\\sinh": "sinh", "\\cosh": "cosh", "\\tanh": "tanh",
    "\\log": "log", "\\ln": "ln", "\\exp": "exp",
    "\\det": "det", "\\dim": "dim", "\\gcd": "gcd",
    "\\neq": "!=", "\\ne": "!=",
    "\\leq": "<=", "\\le": "<=",
    "\\geq": ">=", "\\ge": ">=",
    "\\ll": "<<", "\\gg": ">>",
    "\\approx": "approx", "\\equiv": "equiv", "\\sim": "tilde.op",
    "\\propto": "prop",
    "\\in": "in", "\\notin": "in.not",
    "\\subset": "subset", "\\subseteq": "subset.eq",
    "\\supset": "supset", "\\supseteq": "supset.eq",
    "\\cup": "union", "\\cap": "sect",
    "\\emptyset": "emptyset", "\\varnothing": "nothing",
    "\\cdot": "dot", "\\cdots": "dots.c", "\\ldots": "dots",
    "\\vdots": "dots.v", "\\ddots": "dots.down",
    "\\times": "times", "\\div": "div",
    "\\pm": "plus.minus", "\\mp": "minus.plus",
    "\\oplus": "plus.circle", "\\otimes": "times.circle",
    "\\rightarrow": "->", "\\to": "->",
    "\\leftarrow": "<-",
    "\\Rightarrow": "=>", "\\Leftarrow": "<=",
    "\\leftrightarrow": "<->", "\\Leftrightarrow": "<=>",
    "\\mapsto": "|->",
    "\\neg": "not", "\\land": "and", "\\lor": "or",
    "\\quad": "quad", "\\qquad": "wide",
    "\\,": "thin", "\\;": "med",
    "\\!": "",
    "\\star": "star", "\\circ": "compose",
    "\\lfloor": "floor(", "\\rfloor": ")",
    "\\lceil": "ceil(", "\\rceil": ")",
    "\\langle": "angle.l", "\\rangle": "angle.r",
    "\\prime": "'",
    "\\enspace": "space", "\\hspace": "space",
    "\\displaystyle": "", "\\textstyle": "",
    "\\color{red}": "", "\\color{blue}": "", "\\color{green}": "",
    "\\red": "", "\\blue": "",
  };
  for (const [latex, typst] of Object.entries(symbolMap)) {
    const escaped = latex.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    s = s.replace(new RegExp(escaped + "(?![a-zA-Z])", "g"), typst + " ");
  }

  // \begin{aligned}...\end{aligned} etc. — not perfectly convertible
  s = s.replace(/\\begin\{(aligned|align|cases|pmatrix|bmatrix|vmatrix|matrix|array)\}/g, "");
  s = s.replace(/\\end\{(aligned|align|cases|pmatrix|bmatrix|vmatrix|matrix|array)\}/g, "");

  // \\ (line break in math) → \
  s = s.replace(/\\\\/g, "\\");

  // & (alignment) → keep as-is (Typst also uses &)

  // Clean up: remove remaining single backslashes before unknown commands
  // but be careful not to break valid Typst
  s = s.replace(/\\([a-zA-Z]+)/g, "$1");

  // Clean up multiple spaces
  s = s.replace(/  +/g, " ");

  return s.trim();
}

function convertBody(markdown) {
  const lines = markdown.split(/\r?\n/);
  const out = [];
  let inCodeBlock = false;
  let inBlockquote = false;
  let inDisplayMath = false;
  let displayMathBuf = [];

  for (let i = 0; i < lines.length; i++) {
    let line = lines[i];

    if (line.match(/^```/)) {
      if (inBlockquote) {
        inBlockquote = false;
      }
      inCodeBlock = !inCodeBlock;
      out.push(line);
      continue;
    }

    if (inCodeBlock) {
      out.push(line);
      continue;
    }

    // display math: $$...$$ blocks
    if (inDisplayMath) {
      if (line.trim() === "$$") {
        const mathContent = displayMathBuf.join("\n");
        out.push(`$ ${convertLatexMath(mathContent)} $`);
        inDisplayMath = false;
        displayMathBuf = [];
      } else {
        displayMathBuf.push(line);
      }
      continue;
    }

    if (line.trim() === "$$") {
      inDisplayMath = true;
      displayMathBuf = [];
      continue;
    }

    // single-line display math: $$...$$
    const singleDisplayMatch = line.match(/^\$\$([\s\S]+?)\$\$$/);
    if (singleDisplayMatch) {
      out.push(`$ ${convertLatexMath(singleDisplayMatch[1])} $`);
      continue;
    }

    // strip HTML comments (except <!--more--> already removed)
    line = line.replace(/<!--.*?-->/g, "");

    // horizontal rule
    if (/^(-{3,}|\*{3,}|_{3,})\s*$/.test(line)) {
      out.push("#line(length: 100%)");
      continue;
    }

    // headings: ## → ==
    const headingMatch = line.match(/^(#{1,6})\s+(.*)/);
    if (headingMatch) {
      const level = "=".repeat(headingMatch[1].length);
      out.push(`${level} ${convertInline(headingMatch[2])}`);
      continue;
    }

    // blockquote
    if (line.match(/^>\s?/)) {
      if (!inBlockquote) {
        inBlockquote = true;
        out.push("#quote[");
      }
      out.push(convertInline(line.replace(/^>\s?/, "")));
      continue;
    } else if (inBlockquote) {
      inBlockquote = false;
      out.push("]");
    }

    // ordered list: 1. → +
    const olMatch = line.match(/^(\s*)\d+\.\s+(.*)/);
    if (olMatch) {
      out.push(`${olMatch[1]}+ ${convertInline(olMatch[2])}`);
      continue;
    }

    // unordered list: - or * → -
    const ulMatch = line.match(/^(\s*)[-*]\s+(.*)/);
    if (ulMatch) {
      out.push(`${ulMatch[1]}- ${convertInline(ulMatch[2])}`);
      continue;
    }

    out.push(convertInline(line));
  }

  if (inBlockquote) {
    out.push("]");
  }

  return out.join("\n");
}

function convertInline(text) {
  // bare URLs: <https://...> → #link("url")
  text = text.replace(/<(https?:\/\/[^>]+)>/g, (_, url) => {
    return `#link("${url}")`;
  });

  // images: ![alt](url) → #image("url")
  text = text.replace(/!\[([^\]]*)\]\(([^)]+)\)/g, (_, alt, url) => {
    return `#image("${url}")`;
  });

  // links: [text](url) → #link("url")[text]
  text = text.replace(/\[([^\]]+)\]\(([^)]+)\)/g, (_, linkText, url) => {
    return `#link("${url}")[${linkText}]`;
  });

  // @ → \@ (Typst interprets @foo as label reference)
  text = text.replace(/@/g, "\\@");

  // Escaped asterisks \* → literal * (protect from bold/italic regex)
  text = text.replace(/\\\*/g, "\x05");

  // Protect bold+italic and bold with placeholders before italic pass
  text = text.replace(/\*{3}(.+?)\*{3}/g, "\x01$1\x02");
  text = text.replace(/\*{2}(.+?)\*{2}/g, "\x03$1\x04");

  // italic: *text* → _text_ (bold already replaced, won't double-convert)
  text = text.replace(/(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)/g, "_$1_");

  // Escape remaining unpaired asterisks (e.g. *.example.com)
  text = text.replace(/\*/g, "\\*");

  // Restore bold+italic and bold with Typst syntax
  text = text.replace(/\x01(.*?)\x02/g, "*_$1_*");
  text = text.replace(/\x03(.*?)\x04/g, "*$1*");
  text = text.replace(/\x05/g, "\\*");

  // strikethrough: ~~text~~ → #strike[text]
  text = text.replace(/~~(.+?)~~/g, "#strike[$1]");

  // convert inline math $...$ (but not $$)
  text = text.replace(/(?<!\$)\$(?!\$)([^\$\n]+?)\$(?!\$)/g, (_, math) => {
    return `$${convertLatexMath(math)}$`;
  });

  return text;
}

function buildTypstHeader(meta, description) {
  const titleEsc = escapeTypstString(meta.title);
  const descEsc = escapeTypstString(description);
  const tagsStr = meta.tags.map((t) => `"${escapeTypstString(t)}"`).join(", ");
  const catEsc = escapeTypstString(meta.category);

  let dateStr = "";
  if (meta.date) {
    const d = meta.date;
    dateStr = `datetime(year: ${d.year}, month: ${d.month}, day: ${d.day})`;
  } else {
    dateStr = "datetime.today()";
  }

  return [
    `#import "../../../config.typ": *`,
    ``,
    `#show: template-post.with(`,
    `  title: "${titleEsc}",`,
    `  description: "${descEsc}",`,
    `  tags: (${tagsStr},),`,
    `  category: "${catEsc}",`,
    `  date: ${dateStr}`,
    `)`,
    ``,
  ].join("\n");
}

// --- main ---

const files = walkMd(SOURCE_DIR);
let migrated = 0;
let skipped = 0;
const errors = [];

for (const mdPath of files) {
  const rel = relative(SOURCE_DIR, mdPath);
  const dir = dirname(rel);
  const name = basename(rel, ".md");

  const raw = readFileSync(mdPath, "utf8");
  const meta = parseFrontmatter(raw);
  if (!meta) {
    errors.push(`${rel}: failed to parse frontmatter`);
    continue;
  }

  // category: subdirectory name if in a subdir, else frontmatter
  const category = dir === "." ? meta.category : basename(dir);
  meta.category = category;

  const slug = slugify(name);
  const targetDir = join(TARGET_DIR, slugify(category), slug);

  if (existsSync(targetDir)) {
    skipped++;
    console.log(`SKIP  ${rel} → ${targetDir} (exists)`);
    continue;
  }

  const { description, content } = extractDescription(meta.body);
  const typstBody = convertBody(content);

  let output = "";
  output += buildTypstHeader(meta, description);
  output += typstBody;
  if (!output.endsWith("\n")) output += "\n";

  mkdirSync(targetDir, { recursive: true });
  writeFileSync(join(targetDir, "index.typ"), output, "utf8");
  migrated++;
  console.log(`OK    ${rel} → ${targetDir}`);
}

console.log("\n--- Migration Summary ---");
console.log(`Migrated : ${migrated}`);
console.log(`Skipped  : ${skipped}`);
console.log(`Errors   : ${errors.length}`);
if (errors.length > 0) {
  console.log(`\nErrors:`);
  for (const e of errors) console.log(`  - ${e}`);
}
