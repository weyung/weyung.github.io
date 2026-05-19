import { mkdirSync, rmSync } from "node:fs";
import { basename, dirname, join, relative, resolve } from "node:path";
import {
  ASSETS_DIR,
  ROOT_DIR,
  PAGES_DIR,
  POSTS_DIR,
  TYPE_TOOLCHAIN_DIR,
} from "./constants.mjs";
import {
  assertRouteTokenUsage,
  buildSlugMap,
  collectSourceFiles,
  ensureDirForFile,
  incrementalSync,
  normalizePosixPath,
  pagePathToOutputRel,
  safeRead,
  stageFileFromSourceOrOutput,
  upsertStatus,
  walkFiles,
  writeJson,
} from "./helpers.mjs";
import { createProgressBar } from "./progress.mjs";
import { runPool } from "./pool.mjs";
import { POSTS_PER_PAGE, calcTotalPages, listPages, withPagePath } from "./page.mjs";
import { collectTypstDependencyFiles, makeTypstCompileArgs, parseJsonFromMetadataHtml, runTypstCompile } from "./typst.mjs";
import { SITE_CONFIG_FILE_NAME, stageRss } from "./rss.mjs";

// 仅允许 index.typ 作为页面入口，并推导 page-path。
function derivePagePathFromIndexTyp(baseDir, typFilePath) {
  if (basename(typFilePath).toLowerCase() !== "index.typ") {
    throw new Error(`Only index.typ is supported: ${normalizePosixPath(relative(baseDir, typFilePath))}`);
  }

  const rel = normalizePosixPath(relative(baseDir, typFilePath));
  if (rel === "index.typ") {
    return "";
  }

  return normalizePosixPath(dirname(rel));
}

function readSiteConfigInputs(siteConfigPath) {
  const raw = safeRead(siteConfigPath).trim();
  if (!raw) {
    return { websiteUrl: null, author: null };
  }

  try {
    const parsed = JSON.parse(raw);
    const websiteUrl = String(parsed.siteUrl || "").trim().replace(/\/+$/, "") || null;
    const author = String(parsed.author || "").trim() || null;
    return { websiteUrl, author };
  } catch {
    return { websiteUrl: null, author: null };
  }
}

// 并发提取每篇文章 metadata，汇总成 posts 列表。
async function collectPostMetadata(postTypFiles, jobs, paths) {
  const tasks = postTypFiles.map((typFile) => {
    const rel = normalizePosixPath(relative(POSTS_DIR, typFile));
    return {
      typFile,
      cacheHtmlPath: join(paths.metadataCacheDir, "posts", rel.replace(/\/index\.typ$/i, ""), "meta.html"),
    };
  });

  const progressBar = createProgressBar("metadata    ", tasks.length);
  const results = await runPool(
    tasks,
    jobs,
    async (task) => {
      ensureDirForFile(task.cacheHtmlPath);

      const pagePath = derivePagePathFromIndexTyp(POSTS_DIR, task.typFile);
      const args = makeTypstCompileArgs(ROOT_DIR, task.typFile, task.cacheHtmlPath, [
        ["page-path", pagePath],
        ["emit-post-meta", "true"],
      ]);

      const compiled = await runTypstCompile(ROOT_DIR, task.typFile, args, "metadata");
      if (!compiled.ok) {
        return { ok: false, message: compiled.message };
      }

      const parsed = parseJsonFromMetadataHtml(ROOT_DIR, safeRead(task.cacheHtmlPath), task.typFile);
      rmSync(task.cacheHtmlPath, { force: true });

      return {
        ok: true,
        post: {
          slug: pagePath,
          url: `/posts/${pagePath}/`.replace("//", "/"),
          title: String(parsed.title || "").trim(),
          description: String(parsed.description || "").trim(),
          tags: Array.isArray(parsed.tags)
            ? parsed.tags.map((tag) => String(tag).trim()).filter(Boolean)
            : [],
          category: String(parsed.category || "").trim(),
          date: String(parsed.date || "").trim(),
        },
      };
    },
    progressBar,
  );

  const errors = results.filter((item) => !item.ok);
  if (errors.length > 0) {
    throw new Error(errors.map((item) => item.message).join("\n\n"));
  }

  const posts = results.map((item) => item.post);
  posts.sort((a, b) => {
    const byDate = String(a.date).localeCompare(String(b.date));
    if (byDate !== 0) {
      return byDate;
    }
    return String(a.slug).localeCompare(String(b.slug));
  });

  return posts;
}

// 防止不同任务写入同一个输出路径。
function ensureUniqueOutputTargets(tasks) {
  const seen = new Map();

  for (const task of tasks) {
    const key = normalizePosixPath(task.outputRel);
    const existing = seen.get(key);
    if (existing) {
      throw new Error([
        `Output collision: ${key}`,
        `- ${existing.source}`,
        `- ${task.source}`,
      ].join("\n"));
    }

    seen.set(key, {
      source: `${normalizePosixPath(relative(ROOT_DIR, task.sourceTypFile))}${task.routeLabel ? ` (${task.routeLabel})` : ""}`,
    });
  }
}

// 生成文章编译任务（posts/*/index.typ -> posts/*/index.html）。
function makePostCompileTasks(postTypFiles, postsJsonPath, slugsJsonPath, dependencies, siteInputs = {}) {
  const postsInput = normalizePosixPath(relative(TYPE_TOOLCHAIN_DIR, postsJsonPath));
  const slugsInput = normalizePosixPath(relative(TYPE_TOOLCHAIN_DIR, slugsJsonPath));
  const extraInputs = [];
  if (siteInputs.websiteUrl) {
    extraInputs.push(["website-url", siteInputs.websiteUrl]);
  }
  if (siteInputs.author) {
    extraInputs.push(["author", siteInputs.author]);
  }

  return postTypFiles.map((typFile) => {
    const pagePath = derivePagePathFromIndexTyp(POSTS_DIR, typFile);
    const outputRel = pagePathToOutputRel(`posts/${pagePath}`);

    return {
      kind: "post",
      sourceTypFile: typFile,
      outputRel,
      inputs: [
        ["page-path", pagePath],
        ["posts-json", postsInput],
        ["slugs-json", slugsInput],
        ...extraInputs,
      ],
      dependencies: [...dependencies, postsJsonPath, slugsJsonPath],
      routeLabel: "",
    };
  });
}

// 生成页面编译任务，并展开 [tag]/[category] 动态路由。
function makePageCompileTasks(pageTypFiles, posts, slugMaps, postsJsonPath, slugsJsonPath, dependencies, siteInputs = {}) {
  const postsInput = normalizePosixPath(relative(TYPE_TOOLCHAIN_DIR, postsJsonPath));
  const slugsInput = normalizePosixPath(relative(TYPE_TOOLCHAIN_DIR, slugsJsonPath));
  const extraInputs = [];
  if (siteInputs.websiteUrl) {
    extraInputs.push(["website-url", siteInputs.websiteUrl]);
  }
  if (siteInputs.author) {
    extraInputs.push(["author", siteInputs.author]);
  }

  const tags = Array.from(new Set(posts.flatMap((post) => post.tags))).sort((a, b) => a.localeCompare(b));
  const categories = Array.from(new Set(posts.map((post) => post.category).filter(Boolean))).sort((a, b) => a.localeCompare(b));

  const tasks = [];

  for (const typFile of pageTypFiles) {
    const relTypPath = normalizePosixPath(relative(PAGES_DIR, typFile));
    const usage = assertRouteTokenUsage(relTypPath);

    if (relTypPath === "index.typ") {
      const totalPages = calcTotalPages(posts.length, POSTS_PER_PAGE);
      for (const pageNumber of listPages(totalPages)) {
        const pagePath = withPagePath("", pageNumber);
        tasks.push({
          kind: "page",
          sourceTypFile: typFile,
          outputRel: pagePathToOutputRel(pagePath),
          inputs: [
            ["page-path", pagePath],
            ["posts-json", postsInput],
            ["slugs-json", slugsInput],
            ["route-page", String(pageNumber)],
            ["route-page-size", String(POSTS_PER_PAGE)],
            ...extraInputs,
          ],
          dependencies: [...dependencies, postsJsonPath, slugsJsonPath],
          routeLabel: `page=${pageNumber}`,
        });
      }
      continue;
    }

    if (usage.hasTag) {
      for (const tag of tags) {
        const slug = slugMaps.tags[tag];
        const relTarget = relTypPath.replace("[tag]", slug);
        const basePath = derivePagePathFromIndexTyp(PAGES_DIR, join(PAGES_DIR, relTarget));
        const matchedCount = posts.filter((post) => post.tags.some((value) => value === tag)).length;
        const totalPages = calcTotalPages(matchedCount, POSTS_PER_PAGE);

        for (const pageNumber of listPages(totalPages)) {
          const pagePath = withPagePath(basePath, pageNumber);
          tasks.push({
            kind: "page",
            sourceTypFile: typFile,
            outputRel: pagePathToOutputRel(pagePath),
            inputs: [
              ["page-path", pagePath],
              ["posts-json", postsInput],
              ["slugs-json", slugsInput],
              ["route-tag", tag],
              ["route-page", String(pageNumber)],
              ["route-page-size", String(POSTS_PER_PAGE)],
              ...extraInputs,
            ],
            dependencies: [...dependencies, postsJsonPath, slugsJsonPath],
            routeLabel: `tag=${tag},page=${pageNumber}`,
          });
        }
      }
      continue;
    }

    if (usage.hasCategory) {
      for (const category of categories) {
        const slug = slugMaps.categories[category];
        const relTarget = relTypPath.replace("[category]", slug);
        const basePath = derivePagePathFromIndexTyp(PAGES_DIR, join(PAGES_DIR, relTarget));
        const matchedCount = posts.filter((post) => post.category === category).length;
        const totalPages = calcTotalPages(matchedCount, POSTS_PER_PAGE);

        for (const pageNumber of listPages(totalPages)) {
          const pagePath = withPagePath(basePath, pageNumber);
          tasks.push({
            kind: "page",
            sourceTypFile: typFile,
            outputRel: pagePathToOutputRel(pagePath),
            inputs: [
              ["page-path", pagePath],
              ["posts-json", postsInput],
              ["slugs-json", slugsInput],
              ["route-category", category],
              ["route-page", String(pageNumber)],
              ["route-page-size", String(POSTS_PER_PAGE)],
              ...extraInputs,
            ],
            dependencies: [...dependencies, postsJsonPath, slugsJsonPath],
            routeLabel: `category=${category},page=${pageNumber}`,
          });
        }
      }
      continue;
    }

    const pagePath = derivePagePathFromIndexTyp(PAGES_DIR, typFile);
    tasks.push({
      kind: "page",
      sourceTypFile: typFile,
      outputRel: pagePathToOutputRel(pagePath),
      inputs: [
        ["page-path", pagePath],
        ["posts-json", postsInput],
        ["slugs-json", slugsInput],
        ...extraInputs,
      ],
      dependencies: [...dependencies, postsJsonPath, slugsJsonPath],
      routeLabel: "",
    });
  }

  return tasks;
}

// 全量编译所有 Typst 任务到 staging。
async function compileAndStageTypstTasks(tasks, stagingSiteDir, jobs, statusMap) {
  const compileTasks = tasks.map((task) => ({
    ...task,
    stagingOutputPath: join(stagingSiteDir, task.outputRel),
  }));

  const progressBar = createProgressBar("compile     ", compileTasks.length);
  const results = await runPool(
    compileTasks,
    jobs,
    async (task) => {
      ensureDirForFile(task.stagingOutputPath);
      const args = makeTypstCompileArgs(ROOT_DIR, task.sourceTypFile, task.stagingOutputPath, task.inputs);
      const compiled = await runTypstCompile(ROOT_DIR, task.sourceTypFile, args, task.kind);
      if (!compiled.ok) {
        return {
          ok: false,
          message: compiled.message,
        };
      }

      return { ok: true, outputRel: task.outputRel };
    },
    progressBar,
  );

  const errors = results.filter((item) => !item.ok);
  if (errors.length > 0) {
    throw new Error(errors.map((item) => item.message).join("\n\n"));
  }

  for (const item of results) {
    upsertStatus(statusMap, item.outputRel, "updated");
  }
}

// 复制一组静态资源到 staging，并更新状态统计。
function stageAssetGroup(sourceRoot, sourceFiles, stagingSiteDir, targetPrefix, statusMap, label) {
  const progressBar = createProgressBar(label, sourceFiles.length);

  for (const sourcePath of sourceFiles) {
    const sourceRel = normalizePosixPath(relative(sourceRoot, sourcePath));
    const outputRel = targetPrefix ? normalizePosixPath(`${targetPrefix}/${sourceRel}`) : sourceRel;
    const stagingPath = join(stagingSiteDir, outputRel);

    stageFileFromSourceOrOutput(sourcePath, stagingPath, statusMap, outputRel);
    if (progressBar) {
      progressBar.tick();
    }
  }
}

// 构建主流程：采集 metadata -> 编译页面 -> 合并资源 -> 原子切换输出目录。
export async function buildSite({ outDirName, jobs, configPath, cacheRoot }) {
  const resolvedConfigTypPath = resolve(ROOT_DIR, configPath);
  const resolvedCacheRoot = resolve(ROOT_DIR, cacheRoot);
  const paths = {
    configTypPath: resolvedConfigTypPath,
    siteConfigPath: resolve(ROOT_DIR, SITE_CONFIG_FILE_NAME),
    cacheRoot: resolvedCacheRoot,
    stagingSiteDir: join(resolvedCacheRoot, "_site-staging"),
    metadataCacheDir: join(resolvedCacheRoot, "metadata"),
    postsMetadataJsonPath: join(resolvedCacheRoot, "_posts-metadata.json"),
    routeSlugsJsonPath: join(resolvedCacheRoot, "_route-slugs.json"),
  };
  const outputSiteDir = resolve(ROOT_DIR, outDirName);
  const siteInputs = readSiteConfigInputs(paths.siteConfigPath);

  // Task list:
  // 1. 清空临时文件夹
  // 2. 生成 posts 元数据并汇总 JSON
  // 3. 执行 slugify 并校验冲突
  // 4. 编译 pages/posts 的 index.typ 并写入临时目录
  // 5. 检查 assets/pages/posts 资源并标记 updated 或 unchanged
  // 6. 对比旧 _site 标记 deleted
  // 7. 将临时目录移动到目标输出目录

  // 1) 准备干净的缓存与 staging 目录。
  rmSync(paths.stagingSiteDir, { recursive: true, force: true });
  mkdirSync(paths.stagingSiteDir, { recursive: true });
  mkdirSync(paths.metadataCacheDir, { recursive: true });

  const postSource = collectSourceFiles(POSTS_DIR);
  const pageSource = collectSourceFiles(PAGES_DIR);

  // 2) 提取文章元数据，并生成 slug 映射数据。
  const posts = await collectPostMetadata(postSource.typFiles, jobs, paths);
  writeJson(paths.postsMetadataJsonPath, posts);

  const tagValues = posts.flatMap((post) => post.tags);
  const categoryValues = posts.map((post) => post.category).filter(Boolean);

  const slugMaps = {
    tags: buildSlugMap(tagValues, "tags"),
    categories: buildSlugMap(categoryValues, "categories"),
  };
  writeJson(paths.routeSlugsJsonPath, slugMaps);

  // 3) 组装并校验编译任务。
  const typstDependencies = collectTypstDependencyFiles(paths.configTypPath);
  const postCompileTasks = makePostCompileTasks(
    postSource.typFiles,
    paths.postsMetadataJsonPath,
    paths.routeSlugsJsonPath,
    typstDependencies,
    siteInputs,
  );
  const pageCompileTasks = makePageCompileTasks(
    pageSource.typFiles,
    posts,
    slugMaps,
    paths.postsMetadataJsonPath,
    paths.routeSlugsJsonPath,
    typstDependencies,
    siteInputs,
  );

  const allCompileTasks = [...postCompileTasks, ...pageCompileTasks];
  ensureUniqueOutputTargets(allCompileTasks);

  // 4) 编译 Typst 页面到 staging。
  const statusMap = new Map();
  await compileAndStageTypstTasks(allCompileTasks, paths.stagingSiteDir, jobs, statusMap);

  // 5) 合并静态资源（站点资源 / 文章资源 / 页面资源）。
  const siteAssets = walkFiles(ASSETS_DIR);
  stageAssetGroup(ASSETS_DIR, siteAssets, paths.stagingSiteDir, "assets", statusMap, "assets:site ");
  stageAssetGroup(POSTS_DIR, postSource.assetFiles, paths.stagingSiteDir, "posts", statusMap, "assets:post ");
  stageAssetGroup(PAGES_DIR, pageSource.assetFiles, paths.stagingSiteDir, "", statusMap, "assets:page ");

  // 6) 生成 RSS（输出根目录 rss.xml）。
  stageRss(posts, outputSiteDir, paths.stagingSiteDir, paths.siteConfigPath, statusMap);

  // 7) 计算删除项并完成输出目录切换。
  const syncResult = incrementalSync(paths.stagingSiteDir, outputSiteDir);

  console.log("Build succeeded!");
  console.log(`Out: ${outputSiteDir}`);
  console.log(`@ Compiled   : ${allCompileTasks.length}`);
  console.log(`+ Updated    : ${syncResult.updatedCount}`);
  console.log(`: Unchanged  : ${syncResult.unchangedCount}`);
  console.log(`- Deleted    : ${syncResult.deleted.length}`);
  console.log(`= Total      : ${syncResult.updatedCount + syncResult.unchangedCount + syncResult.deleted.length}`);
  console.log("");
  console.log(`- Posts      : ${posts.length}`);
  console.log(`- Tags       : ${Object.keys(slugMaps.tags).length}`);
  console.log(`- Categories : ${Object.keys(slugMaps.categories).length}`);
}
