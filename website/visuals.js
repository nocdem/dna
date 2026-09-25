// Decorative enhancement only; page content and navigation work without it.
const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
const finePointer = window.matchMedia('(hover: hover) and (pointer: fine)');
const revealItems = [...document.querySelectorAll('[data-reveal]')];
let revealObserver;

function configureReveals() {
  revealObserver?.disconnect();
  revealItems.forEach(element => element.classList.remove('reveal-pending'));
  if (reducedMotion.matches || !('IntersectionObserver' in window)) return;
  revealObserver = new IntersectionObserver(entries => {
    entries.forEach(({ target, isIntersecting }) => {
      if (!isIntersecting) return;
      target.classList.remove('reveal-pending');
      revealObserver.unobserve(target);
    });
  }, { threshold: 0.04, rootMargin: '0px 0px 35px 0px' });
  revealItems.forEach(element => {
    // Leave content already on screen visible, including browser Back restores.
    if (element.getBoundingClientRect().top <= innerHeight) return;
    element.classList.add('reveal-pending');
    revealObserver.observe(element);
  });
}

configureReveals();
reducedMotion.addEventListener('change', configureReveals);
document.addEventListener('focusin', event => {
  const element = event.target.closest('[data-reveal]');
  element?.classList.remove('reveal-pending');
  if (element) revealObserver?.unobserve(element);
});

const depthItems = [...document.querySelectorAll('[data-depth]')];
const resetDepth = element => {
  element.style.removeProperty('--pointer-x');
  element.style.removeProperty('--pointer-y');
  element.style.removeProperty('--turn-x');
  element.style.removeProperty('--turn-y');
};

depthItems.forEach(element => {
  let frame = 0;
  let point;
  element.addEventListener('pointermove', event => {
    if (reducedMotion.matches || !finePointer.matches) return;
    point = { x: event.clientX, y: event.clientY };
    if (frame) return;
    frame = requestAnimationFrame(() => {
      frame = 0;
      if (reducedMotion.matches || !finePointer.matches) return;
      const bounds = element.getBoundingClientRect();
      const x = Math.max(0, Math.min(1, (point.x - bounds.left) / bounds.width));
      const y = Math.max(0, Math.min(1, (point.y - bounds.top) / bounds.height));
      element.style.setProperty('--pointer-x', `${x * 100}%`);
      element.style.setProperty('--pointer-y', `${y * 100}%`);
      element.style.setProperty('--turn-x', `${(0.5 - y) * 2}deg`);
      element.style.setProperty('--turn-y', `${(x - 0.5) * 2}deg`);
    });
  });
  element.addEventListener('pointerleave', () => {
    cancelAnimationFrame(frame);
    frame = 0;
    resetDepth(element);
  });
});

function resetAllDepth() { depthItems.forEach(resetDepth); }
reducedMotion.addEventListener('change', resetAllDepth);
finePointer.addEventListener('change', resetAllDepth);

const progress = document.querySelector('.reading-progress');
const header = document.querySelector('.site-header');
let scrollFrame = 0;
function updateScroll() {
  scrollFrame = 0;
  const distance = document.documentElement.scrollHeight - innerHeight;
  const fraction = distance > 0 ? Math.min(1, Math.max(0, scrollY / distance)) : 0;
  if (progress) progress.style.transform = `scaleX(${fraction})`;
  header?.classList.toggle('header-scrolled', scrollY > 24);
}
function scheduleScroll() {
  if (!scrollFrame) scrollFrame = requestAnimationFrame(updateScroll);
}
window.addEventListener('scroll', scheduleScroll, { passive: true });
window.addEventListener('resize', scheduleScroll);
window.addEventListener('pageshow', scheduleScroll);
if ('ResizeObserver' in window) new ResizeObserver(scheduleScroll).observe(document.body);
updateScroll();
