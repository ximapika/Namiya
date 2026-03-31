document.addEventListener('DOMContentLoaded', () => {
  const carousel = document.querySelector('[data-carousel]');
  if (!carousel) {
    return;
  }

  const slides = Array.from(carousel.querySelectorAll('[data-slide]'));
  const choices = Array.from(carousel.querySelectorAll('[data-slide-to]'));
  const prevButton = carousel.querySelector('.promo-nav-prev');
  const nextButton = carousel.querySelector('.promo-nav-next');

  if (slides.length === 0) {
    return;
  }

  let currentIndex = slides.findIndex((slide) => slide.classList.contains('is-active'));
  let timerId = null;

  if (currentIndex < 0) {
    currentIndex = 0;
  }

  const render = (nextIndex) => {
    currentIndex = nextIndex;

    slides.forEach((slide, index) => {
      const isActive = index === currentIndex;
      slide.classList.toggle('is-active', isActive);
      slide.setAttribute('aria-hidden', String(!isActive));
    });

    choices.forEach((choice, index) => {
      const isActive = index === currentIndex;
      choice.classList.toggle('is-active', isActive);
      choice.setAttribute('aria-pressed', String(isActive));
    });
  };

  const move = (step) => {
    const nextIndex = (currentIndex + step + slides.length) % slides.length;
    render(nextIndex);
  };

  const stopAutoplay = () => {
    if (timerId) {
      window.clearInterval(timerId);
      timerId = null;
    }
  };

  const startAutoplay = () => {
    if (slides.length < 2) {
      return;
    }

    stopAutoplay();
    timerId = window.setInterval(() => move(1), 5500);
  };

  choices.forEach((choice) => {
    choice.addEventListener('click', () => {
      render(Number(choice.dataset.slideTo));
      startAutoplay();
    });
  });

  if (prevButton) {
    prevButton.addEventListener('click', () => {
      move(-1);
      startAutoplay();
    });
  }

  if (nextButton) {
    nextButton.addEventListener('click', () => {
      move(1);
      startAutoplay();
    });
  }

  carousel.addEventListener('mouseenter', stopAutoplay);
  carousel.addEventListener('mouseleave', startAutoplay);
  carousel.addEventListener('focusin', stopAutoplay);
  carousel.addEventListener('focusout', startAutoplay);

  render(currentIndex);
  startAutoplay();
});
