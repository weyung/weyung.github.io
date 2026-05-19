import { extname, relative } from "node:path";
import { spawn } from "node:child_process";
import { ROOT_DIR, TYPE_TOOLCHAIN_DIR } from "./constants.mjs";
import { normalizePosixPath, walkFiles } from "./helpers.mjs";

// 组装 typst compile 参数，并注入 --input 变量。
export function makeTypstCompileArgs(rootDir, sourcePath, outputPath, inputEntries = []) {
  const args = [
    "compile",
    "--root",
    ".",
    "--font-path",
    "assets",
    "--features",
    "html",
    "--format",
    "html",
  ];

  for (const [key, value] of inputEntries) {
    args.push("--input", `${key}=${value}`);
  }

  args.push(
    normalizePosixPath(relative(rootDir, sourcePath)),
    normalizePosixPath(relative(rootDir, outputPath)),
  );

  return args;
}

// 调用 typst 编译单个文件，返回统一的 ok/message 结果。
export function runTypstCompile(rootDir, sourcePath, args, label) {
  return new Promise((resolvePromise) => {
    const child = spawn("typst", args, {
      cwd: rootDir,
      stdio: ["ignore", "ignore", "pipe"],
      windowsHide: true,
    });

    let stderr = "";
    child.stderr.on("data", (chunk) => {
      stderr += String(chunk);
    });

    child.on("close", (code) => {
      if (code === 0) {
        resolvePromise({ ok: true });
        return;
      }

      resolvePromise({
        ok: false,
        message: `Typst ${label} compile failed: ${normalizePosixPath(relative(rootDir, sourcePath))}\n${stderr.trim() || "Unknown error"}`,
      });
    });
  });
}

// 从 metadata HTML 中提取 JSON 块并解析。
export function parseJsonFromMetadataHtml(rootDir, html, sourcePath) {
  const bodyMatch = html.match(/<body[^>]*>([\s\S]*?)<\/body>/i);
  const body = bodyMatch ? bodyMatch[1] : html;
  const jsonMatch = body.match(/\{[\s\S]*\}/);
  let jsonText = jsonMatch ? jsonMatch[0].trim() : "";

  if (!jsonText) {
    throw new Error(`Metadata JSON missing: ${normalizePosixPath(relative(rootDir, sourcePath))}`);
  }

  // 还原 Typst 生成的 HTML 转义字符，避免 &amp; 等符号被带入到 JSON 中导致二次转义
  jsonText = jsonText
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, "\"")
    .replace(/&#39;/g, "'")
    .replace(/&#x27;/g, "'");

  try {
    return JSON.parse(jsonText);
  } catch {
    throw new Error(`Metadata JSON invalid: ${normalizePosixPath(relative(rootDir, sourcePath))}`);
  }
}

// 收集会影响编译缓存判断的 Typst 依赖文件。
export function collectTypstDependencyFiles(configTypPath) {
  const dependencies = [configTypPath];
  const libTyps = walkFiles(TYPE_TOOLCHAIN_DIR, (filePath) => extname(filePath).toLowerCase() === ".typ");
  dependencies.push(...libTyps);
  return dependencies.filter((filePath, index, array) => array.indexOf(filePath) === index);
}
