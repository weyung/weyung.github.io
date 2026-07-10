const SEARCH_LOCALE = 'zh-CN';
const SEARCH_FOCUSABLE_SELECTOR = [
  'a[href]',
  'button:not([disabled])',
  'input:not([disabled])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  '[tabindex]:not([tabindex="-1"])',
].join(',');

const normalizeSearchText = (value) => {
  return String(value || '')
    .normalize('NFKC')
    .toLocaleLowerCase(SEARCH_LOCALE);
};

const isTextSelectionActive = () => {
  const selection = window.getSelection();
  return Boolean(selection && !selection.isCollapsed && selection.toString().trim().length > 0);
};

const createElement = (tagName, className, text) => {
  const element = document.createElement(tagName);
  if (className) {
    element.className = className;
  }
  if (text !== undefined) {
    element.textContent = text;
  }
  return element;
};

const getQueryTerms = (query) => {
  const seenTerms = new Set();
  return normalizeSearchText(query)
    .split(/\s+/)
    .filter(Boolean)
    .filter((term) => {
      if (seenTerms.has(term)) {
        return false;
      }
      seenTerms.add(term);
      return true;
    })
    .sort((a, b) => b.length - a.length);
};

const appendHighlightedText = (parent, value, terms) => {
  const text = String(value || '');
  if (!text || terms.length === 0) {
    parent.append(document.createTextNode(text));
    return;
  }

  const normalizedText = normalizeSearchText(text);
  let index = 0;

  while (index < text.length) {
    let matchedTerm = '';

    for (const term of terms) {
      if (normalizedText.startsWith(term, index)) {
        matchedTerm = term;
        break;
      }
    }

    if (!matchedTerm) {
      parent.append(document.createTextNode(text[index]));
      index += 1;
      continue;
    }

    const mark = createElement('mark', 'site-search-highlight', text.slice(index, index + matchedTerm.length));
    parent.append(mark);
    index += matchedTerm.length;
  }
};

const fetchSearchPosts = async (dataNode) => {
  if (!dataNode) {
    throw new Error('Search index configuration is missing');
  }

  const indexPath = dataNode.getAttribute('data-search-index') || '/search-index.json';
  const response = await fetch(indexPath, { cache: 'no-cache' });
  if (!response.ok) {
    throw new Error(`Search index request failed with status ${response.status}`);
  }

  const posts = await response.json();
  if (!Array.isArray(posts)) {
    throw new Error('Search index has an invalid format');
  }

  return posts;
};

const getPostSearchText = (post) => {
  return normalizeSearchText([
    post.title,
    post.content,
  ].filter(Boolean).join(' '));
};

const getMatchSnippets = (post, terms) => {
  const content = String(post.content || '').replace(/\s+/g, ' ').trim();
  if (!content) {
    return [];
  }

  const normalizedTitle = normalizeSearchText(post.title);
  const normalizedContent = normalizeSearchText(content);
  const ranges = terms
    .filter((term) => !normalizedTitle.includes(term))
    .map((term) => normalizedContent.indexOf(term))
    .filter((index) => index >= 0)
    .map((index) => ({
      start: Math.max(0, index - 80),
      end: Math.min(content.length, index + 160),
    }))
    .sort((a, b) => a.start - b.start);

  if (ranges.length === 0) {
    return [];
  }

  const mergedRanges = [];
  for (const range of ranges) {
    const previous = mergedRanges[mergedRanges.length - 1];
    if (previous && range.start <= previous.end) {
      previous.end = Math.max(previous.end, range.end);
    } else {
      mergedRanges.push({ ...range });
    }
  }

  return mergedRanges.map(({ start, end }) => {
    const prefix = start > 0 ? '...' : '';
    const suffix = end < content.length ? '...' : '';
    return `${prefix}${content.slice(start, end)}${suffix}`;
  });
};

const scorePost = (post, terms) => {
  const title = normalizeSearchText(post.title);
  const content = normalizeSearchText(post.content);
  let score = 0;

  for (const term of terms) {
    if (title.includes(term)) {
      score += 8;
    }
    if (content.includes(term)) {
      score += 1;
    }
  }

  return score;
};

const searchPosts = (posts, query) => {
  const terms = getQueryTerms(query);
  if (terms.length === 0) {
    return [];
  }

  return posts
    .filter((post) => terms.every((term) => post.searchText.includes(term)))
    .map((post) => ({
      ...post,
      score: scorePost(post, terms),
      snippets: getMatchSnippets(post, terms),
    }))
    .sort((a, b) => {
      if (b.score !== a.score) {
        return b.score - a.score;
      }
      return String(b.date).localeCompare(String(a.date));
    });
};

const renderPostCard = (post, terms) => {
  const card = createElement('article', 'site-search-result');
  card.dataset.postUrl = post.url;

  const title = createElement('h3', 'site-search-result-title');
  const titleLink = createElement('a', 'site-search-result-link');
  titleLink.href = post.url;
  appendHighlightedText(titleLink, post.title, terms);
  title.append(titleLink);

  card.append(title);

  for (const snippetText of post.snippets) {
    const snippet = createElement('div', 'site-search-snippet');
    appendHighlightedText(snippet, snippetText, terms);
    card.append(snippet);
  }

  card.append(createElement('div', 'site-search-result-date', post.dateText || post.date));
  return card;
};

const renderEmptyState = () => {
  return createElement('div', 'site-search-empty', '没有找到相关文章');
};

const renderLoadError = (onRetry) => {
  const state = createElement('div', 'site-search-empty site-search-load-error');
  state.append(createElement('div', 'site-search-load-error-message', '搜索索引暂时不可用'));

  const retryButton = createElement('button', 'site-search-retry', '重试');
  retryButton.type = 'button';
  retryButton.addEventListener('click', onRetry);
  state.append(retryButton);
  return state;
};

const installSearchResultCards = (results) => {
  results.addEventListener('click', (event) => {
    if (isTextSelectionActive()) {
      return;
    }

    const interactiveTarget = event.target.closest('a, button, input, select, textarea, [role="button"]');
    if (interactiveTarget) {
      return;
    }

    const card = event.target.closest('[data-post-url]');
    const url = card && card.getAttribute('data-post-url');
    if (url) {
      window.location.href = url;
    }
  });
};

const installHomeSearch = () => {
  const openButton = document.querySelector('.nav-search-switch');
  const overlay = document.querySelector('#site-search-overlay');
  const dialog = document.querySelector('#site-search-dialog');
  const closeButton = document.querySelector('.site-search-close');
  const input = document.querySelector('#site-search-input');
  const dataNode = document.querySelector('#site-search-data');
  const results = document.querySelector('#site-search-results');
  const status = document.querySelector('#site-search-status');

  if (!openButton || !overlay || !dialog || !closeButton || !input || !dataNode || !results || !status) {
    return;
  }

  let previousFocus = null;
  let postsPromise = null;
  let renderToken = 0;
  const backgroundInertStates = new Map();

  const setBackgroundInert = (enabled) => {
    if (!enabled) {
      for (const [element, wasInert] of backgroundInertStates) {
        if (!wasInert) {
          element.removeAttribute('inert');
        }
      }
      backgroundInertStates.clear();
      return;
    }

    let branch = overlay;
    while (branch && branch !== document.body) {
      const parent = branch.parentElement;
      if (!parent) {
        break;
      }

      for (const sibling of parent.children) {
        if (sibling === branch || !(sibling instanceof HTMLElement)) {
          continue;
        }
        if (!backgroundInertStates.has(sibling)) {
          backgroundInertStates.set(sibling, sibling.hasAttribute('inert'));
        }
        sibling.setAttribute('inert', '');
      }
      branch = parent;
    }
  };

  const keepFocusInDialog = (event) => {
    const focusableElements = Array.from(dialog.querySelectorAll(SEARCH_FOCUSABLE_SELECTOR))
      .filter((element) => element.getClientRects().length > 0);

    if (focusableElements.length === 0) {
      event.preventDefault();
      dialog.focus();
      return;
    }

    const firstElement = focusableElements[0];
    const lastElement = focusableElements[focusableElements.length - 1];
    const activeElement = document.activeElement;

    if (!dialog.contains(activeElement)) {
      event.preventDefault();
      firstElement.focus();
    } else if (event.shiftKey && activeElement === firstElement) {
      event.preventDefault();
      lastElement.focus();
    } else if (!event.shiftKey && activeElement === lastElement) {
      event.preventDefault();
      firstElement.focus();
    }
  };

  const loadPosts = () => {
    if (!postsPromise) {
      postsPromise = fetchSearchPosts(dataNode)
        .then((posts) => posts.map((post) => ({
          ...post,
          searchText: getPostSearchText(post),
        })))
        .catch((error) => {
          postsPromise = null;
          throw error;
        });
    }

    return postsPromise;
  };

  const renderResults = async () => {
    const token = renderToken + 1;
    renderToken = token;
    const query = input.value.trim();
    results.replaceChildren();

    if (!query) {
      results.hidden = true;
      status.textContent = '输入关键词开始搜索';
      return;
    }

    status.textContent = '正在搜索...';
    let posts;
    try {
      posts = await loadPosts();
    } catch (error) {
      if (token !== renderToken) {
        return;
      }

      results.hidden = false;
      status.textContent = '搜索索引加载失败';
      results.append(renderLoadError(renderResults));
      return;
    }

    if (token !== renderToken) {
      return;
    }

    const matchedPosts = searchPosts(posts, query);
    results.hidden = false;

    if (matchedPosts.length === 0) {
      status.textContent = '没有找到相关文章';
      results.append(renderEmptyState());
      return;
    }

    status.textContent = `找到 ${matchedPosts.length} 篇文章`;
    const terms = getQueryTerms(query);
    const fragment = document.createDocumentFragment();
    for (const post of matchedPosts) {
      fragment.append(renderPostCard(post, terms));
    }
    results.append(fragment);
  };

  const resetSearch = () => {
    renderToken += 1;
    input.value = '';
    results.replaceChildren();
    results.hidden = true;
    status.textContent = '输入关键词开始搜索';
  };

  const openSearch = () => {
    if (!overlay.hidden) {
      return;
    }

    previousFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    resetSearch();
    overlay.hidden = false;
    setBackgroundInert(true);
    openButton.setAttribute('aria-expanded', 'true');
    document.documentElement.classList.add('site-search-open');
    requestAnimationFrame(() => {
      input.focus();
      input.select();
    });
  };

  const closeSearch = () => {
    overlay.hidden = true;
    openButton.setAttribute('aria-expanded', 'false');
    document.documentElement.classList.remove('site-search-open');
    resetSearch();
    setBackgroundInert(false);
    if (previousFocus && typeof previousFocus.focus === 'function') {
      previousFocus.focus();
    }
  };

  openButton.addEventListener('click', openSearch);
  closeButton.addEventListener('click', closeSearch);
  overlay.addEventListener('click', (event) => {
    if (event.target === overlay) {
      closeSearch();
    }
  });
  document.addEventListener('keydown', (event) => {
    if (overlay.hidden) {
      return;
    }

    if (event.key === 'Escape') {
      closeSearch();
    } else if (event.key === 'Tab') {
      keepFocusInDialog(event);
    }
  });
  input.addEventListener('input', renderResults);
  input.addEventListener('search', renderResults);
  input.addEventListener('keydown', (event) => {
    if (event.key !== 'Enter') {
      return;
    }

    const firstCard = results.querySelector('[data-post-url]');
    const url = firstCard && firstCard.getAttribute('data-post-url');
    if (url) {
      window.location.href = url;
    }
  });

  installSearchResultCards(results);
  renderResults();
};

document.addEventListener('DOMContentLoaded', () => {
  installHomeSearch();
});
