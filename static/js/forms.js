document.addEventListener("submit", event => {
    const button = event.submitter;
    const message = button && button.dataset.confirm;
    if (message && !window.confirm(message)) event.preventDefault();
});
