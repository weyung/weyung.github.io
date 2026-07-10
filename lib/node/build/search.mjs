import { existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { ensureDirForFile, safeRead, upsertStatus } from "./helpers.mjs";

function normalizeSearchContent(content) {
  return String(content || "")
    .replace(/\r\n?/g, "\n")
    .replace(/^(?:#import[^\n]*\n\s*)+/, "")
    .replace(/^#show:\s*template-post\.with\([\s\S]*?\n\)\s*\n+/, "")
    .replace(/^\s*#line\s*\([^)]*\)\s*$/gm, "\n")
    .replace(/^\s*=+\s*/gm, "")
    .replace(/#(?:quote|note|success|warning|error)\s*(?:\([^)]*\))?\s*\[([^\]\n]*)\]/g, "\n$1")
    .replace(/#(?:quote|note|success|warning|error)\s*(?:\([^)]*\))?\s*\[/g, "\n")
    .replace(/#link\((?:"[^"]+"|<[^>]+>)\)\s*\[([^\]\n]*)\]/g, "$1")
    .replace(/#link\((?:"[^"]+"|<[^>]+>)\)/g, " ")
    .replace(/#(?:text|underline|strike|overline|super|sub|highlight)\s*(?:\([^)]*\))?\s*\[([^\]\n]*)\]/g, "$1")
    .replace(/#(?:image|figure)\s*\([^)]*\)/g, " ")
    .replace(/^\s*\]\s*$/gm, "\n")
    .replace(/[ \t]+/g, " ")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

export function stageSearchIndex(posts, slugMaps, outputSiteDir, stagingSiteDir, statusMap) {
  const index = posts.map((post) => {
    const categorySlug = post.category ? slugMaps.categories[post.category] || post.category : "";

    return {
      title: post.title,
      description: post.description,
      category: post.category,
      categorySlug,
      tags: post.tags.map((tag) => ({
        name: tag,
        slug: slugMaps.tags[tag] || tag,
      })),
      date: post.date,
      url: post.url,
      content: normalizeSearchContent(post._searchContent),
    };
  });

  const outputRel = "search-index.json";
  const oldOutputPath = join(outputSiteDir, outputRel);
  const stagingPath = join(stagingSiteDir, outputRel);
  const json = `${JSON.stringify(index)}\n`;

  ensureDirForFile(stagingPath);
  const unchanged = existsSync(oldOutputPath) && safeRead(oldOutputPath) === json;
  writeFileSync(stagingPath, json, "utf8");
  upsertStatus(statusMap, outputRel, unchanged ? "unchanged" : "updated");
}
