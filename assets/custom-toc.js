document.addEventListener('DOMContentLoaded', () => {
  const content = document.querySelector('article > section');
  if (!content) return;

  // Find all headings from h2 to h6
  const headings = Array.from(content.querySelectorAll('h2, h3, h4, h5, h6'));
  if (headings.length === 0) return;

  // Create backdrop for mobile drawer
  const backdrop = document.createElement('div');
  backdrop.className = 'custom-toc-backdrop';
  document.body.appendChild(backdrop);

  // Create TOC Container
  const tocContainer = document.createElement('div');
  tocContainer.className = 'custom-toc';
  
  const tocTitle = document.createElement('div');
  tocTitle.className = 'custom-toc-title';
  tocTitle.innerText = '目录';
  tocContainer.appendChild(tocTitle);

  const tocList = document.createElement('ul');
  tocContainer.appendChild(tocList);

  const tocLinks = [];

  headings.forEach((h, index) => {
    // Generate id for anchor link if it doesn't have one
    if (!h.id) {
      h.id = 'heading-' + index;
    }

    const li = document.createElement('li');
    li.className = 'toc-item toc-' + h.tagName.toLowerCase();
    
    const a = document.createElement('a');
    a.href = '#' + h.id;
    a.innerText = h.innerText;
    
    li.appendChild(a);
    tocList.appendChild(li);
    tocLinks.push({ heading: h, link: a });

    // Auto-close drawer on mobile when a link is clicked
    a.addEventListener('click', () => {
      closeToc();
    });
  });

  // Append TOC to body so it escapes the article container restrictions
  document.body.appendChild(tocContainer);

  // Create Toggle Button for mobile
  const toggleBtn = document.createElement('button');
  toggleBtn.className = 'custom-toc-toggle';
  toggleBtn.setAttribute('aria-label', 'Toggle Table of Contents');
  document.body.appendChild(toggleBtn);

  const openToc = () => {
    tocContainer.classList.add('custom-toc-open');
    backdrop.classList.add('custom-toc-open');
  };

  const closeToc = () => {
    tocContainer.classList.remove('custom-toc-open');
    backdrop.classList.remove('custom-toc-open');
  };

  toggleBtn.addEventListener('click', openToc);
  backdrop.addEventListener('click', closeToc);

  // Scroll spy implementation
  const onScroll = () => {
    // 1. Desktop sticky behavior
    if (window.innerWidth >= 1440) {
      const scrollY = window.scrollY;
      const initialTop = 15 * 16; // 14rem
      const minTop = 6 * 16;      // 6rem
      
      const currentTop = Math.max(minTop, initialTop - scrollY);
      tocContainer.style.top = `${currentTop}px`;
      tocContainer.style.maxHeight = `calc(100vh - ${currentTop + 32}px)`; // 2rem padding at bottom
    } else {
      tocContainer.style.top = '';
      tocContainer.style.maxHeight = '';
    }

    // 2. Scroll spy highlighting
    let current = null;
    const scrollYForSpy = window.scrollY + 120; // Offset for fixed header + breathing room

    headings.forEach(h => {
      if (scrollYForSpy >= h.offsetTop) {
        current = h;
      }
    });

    tocLinks.forEach(item => {
      item.link.classList.remove('active');
      if (current && item.heading === current) {
        item.link.classList.add('active');
      }
    });
  };

  window.addEventListener('scroll', onScroll, { passive: true });
  window.addEventListener('resize', onScroll, { passive: true });
  onScroll(); // trigger once on load
});
