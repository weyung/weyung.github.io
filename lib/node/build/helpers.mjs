import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { basename, dirname, extname, join, relative } from "node:path";

// 统一路径分隔符，避免 Windows 路径影响后续比较
export function normalizePosixPath(pathValue) {
  return pathValue.replace(/\\/g, "/");
}

// 安全读取文本文件，读取失败时返回空字符串
export function safeRead(filePath) {
  try {
    return readFileSync(filePath, "utf8");
  } catch {
    return "";
  }
}

// 深度遍历目录并按条件收集文件
export function walkFiles(dir, predicate = () => true) {
  if (!existsSync(dir)) {
    return [];
  }

  const files = [];
  const stack = [dir];

  while (stack.length > 0) {
    const current = stack.pop();
    const children = readdirSync(current, { withFileTypes: true });

    for (const child of children) {
      const abs = join(current, child.name);
      if (child.isDirectory()) {
        stack.push(abs);
      } else if (predicate(abs)) {
        files.push(abs);
      }
    }
  }

  return files;
}

// 为目标文件创建父级目录
export function ensureDirForFile(filePath) {
  mkdirSync(dirname(filePath), { recursive: true });
}

// 写入 JSON 文件
export function writeJson(filePath, value) {
  ensureDirForFile(filePath);
  writeFileSync(filePath, `${JSON.stringify(value)}\n`, "utf8");
}

// 将 page-path 转换为输出 html 相对路径
export function pagePathToOutputRel(pagePath) {
  const normalized = String(pagePath || "").replace(/^\/+|\/+$/g, "");
  return normalized ? `${normalized}/index.html` : "index.html";
}

// 收集源目录：仅 index.typ 参与编译，其它非 html 文件视为资源
export function collectSourceFiles(sourceDir) {
  if (!existsSync(sourceDir)) {
    return {
      typFiles: [],
      assetFiles: [],
    };
  }

  const files = walkFiles(sourceDir);
  const typFiles = [];
  const assetFiles = [];

  for (const file of files) {
    const ext = extname(file).toLowerCase();

    if (ext === ".typ") {
      const name = basename(file);
      if (name === "index.typ") {
        typFiles.push(file);
      }
      continue;
    }

    if (ext === ".html") {
      continue;
    }

    assetFiles.push(file);
  }

  typFiles.sort((a, b) => normalizePosixPath(relative(sourceDir, a)).localeCompare(normalizePosixPath(relative(sourceDir, b))));
  assetFiles.sort((a, b) => normalizePosixPath(relative(sourceDir, a)).localeCompare(normalizePosixPath(relative(sourceDir, b))));

  return {
    typFiles,
    assetFiles,
  };
}

// 文本 slugify，用于标签/分类路由
export function slugify(input) {
  return String(input || "")
    .trim()
    .toLowerCase()
    .replace(/\s+/g, "-")
    .replace(/[^\p{L}\p{N}\-_.~]/gu, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "");
}

// 生成 value -> slug 映射，并校验冲突
export function buildSlugMap(values, label) {
  const uniqueValues = Array.from(new Set(values.map((value) => String(value).trim()).filter(Boolean)));
  uniqueValues.sort((a, b) => a.localeCompare(b));

  const slugToValues = new Map();
  const valueToSlug = {};

  for (const value of uniqueValues) {
    const slug = slugify(value);
    const previous = slugToValues.get(slug) || [];
    previous.push(value);
    slugToValues.set(slug, previous);
    valueToSlug[value] = slug;
  }

  const collisions = [];
  for (const [slug, grouped] of slugToValues.entries()) {
    if (grouped.length > 1) {
      collisions.push({ slug, values: grouped });
    }
  }

  if (collisions.length > 0) {
    const lines = collisions.map((item) => `slug "${item.slug}" <- ${item.values.join(" | ")}`);
    throw new Error(`Slug conflict detected in ${label}:\n${lines.join("\n")}`);
  }

  return valueToSlug;
}

// 校验动态路由占位符使用规则（[tag] 和 [category] 只能出现一次且不能共存）
export function assertRouteTokenUsage(relTypPath) {
  const tagCount = (relTypPath.match(/\[tag\]/g) || []).length;
  const categoryCount = (relTypPath.match(/\[category\]/g) || []).length;

  if (tagCount > 1) {
    throw new Error(`Route token [tag] must appear at most once: ${relTypPath}`);
  }

  if (categoryCount > 1) {
    throw new Error(`Route token [category] must appear at most once: ${relTypPath}`);
  }

  if (tagCount > 0 && categoryCount > 0) {
    throw new Error(`Route template cannot include both [tag] and [category]: ${relTypPath}`);
  }

  return {
    hasTag: tagCount === 1,
    hasCategory: categoryCount === 1,
  };
}

// 更新状态：updated 优先级高于 unchanged
export function upsertStatus(statusMap, relPath, status) {
  const key = normalizePosixPath(relPath);
  const current = statusMap.get(key);

  if (!current) {
    statusMap.set(key, status);
    return;
  }

  if (current === "updated") {
    return;
  }

  if (status === "updated") {
    statusMap.set(key, "updated");
  }
}

function fileContentEqual(pathA, pathB) {
  try {
    const statA = statSync(pathA);
    const statB = statSync(pathB);
    if (statA.size !== statB.size) return false;
    return readFileSync(pathA).equals(readFileSync(pathB));
  } catch {
    return false;
  }
}

// 从 source 复制到 staging
export function stageFileFromSourceOrOutput(sourcePath, stagingPath, statusMap, relPath) {
  ensureDirForFile(stagingPath);
  cpSync(sourcePath, stagingPath, { force: true });
  upsertStatus(statusMap, relPath, "updated");
}

// 增量同步 staging → output：仅复制变更文件，删除多余文件。
export function incrementalSync(stagingDir, outputDir) {
  mkdirSync(outputDir, { recursive: true });

  const stagingFiles = walkFiles(stagingDir);
  const stagingRelSet = new Set();
  for (const f of stagingFiles) {
    stagingRelSet.add(normalizePosixPath(relative(stagingDir, f)));
  }

  const outputFiles = walkFiles(outputDir);
  const deleted = [];
  for (const outputPath of outputFiles) {
    const rel = normalizePosixPath(relative(outputDir, outputPath));
    if (!stagingRelSet.has(rel)) {
      rmSync(outputPath, { force: true });
      deleted.push(rel);
    }
  }

  let updatedCount = 0;
  let unchangedCount = 0;
  for (const stagingPath of stagingFiles) {
    const rel = normalizePosixPath(relative(stagingDir, stagingPath));
    const outputPath = join(outputDir, rel);

    if (fileContentEqual(stagingPath, outputPath)) {
      unchangedCount++;
    } else {
      ensureDirForFile(outputPath);
      cpSync(stagingPath, outputPath, { force: true });
      updatedCount++;
    }
  }

  rmSync(stagingDir, { recursive: true, force: true });

  return { updatedCount, unchangedCount, deleted };
}
