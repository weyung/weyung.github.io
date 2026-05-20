const isTextSelectionActive = () => {
  const selection = window.getSelection();
  return Boolean(selection && !selection.isCollapsed && selection.toString().trim().length > 0);
};

const installPostCardClick = () => {
  const cards = document.querySelectorAll('[data-post-url]');
  if (cards.length === 0) {
    return;
  }

  cards.forEach((card) => {
    card.addEventListener('click', (event) => {
      if (isTextSelectionActive()) {
        return;
      }

      const interactiveTarget = event.target.closest('a, button, input, select, textarea, [role="button"]');
      if (interactiveTarget) {
        return;
      }

      const url = card.getAttribute('data-post-url');
      if (!url) {
        return;
      }

      const target = card.getAttribute('data-post-target');
      if (target === '_blank') {
        window.open(url, '_blank');
      } else {
        window.location.href = url;
      }
    });
  });
};

document.addEventListener('DOMContentLoaded', () => {
  installPostCardClick();
});
