/* RSA-OAEP-SHA256 envelopes using the pinned, locally served node-forge library.
 * HTTPS remains necessary to authenticate these scripts and the server key.
 */
(() => {
    "use strict";

    function showError(container, selector, message) {
        let output = container.querySelector(selector);
        if (!output) {
            output = document.createElement("p");
            output.setAttribute(selector.slice(1, -1), "");
            output.setAttribute("role", "alert");
            container.appendChild(output);
        }
        output.textContent = message;
    }

    function hidden(form, name, value) {
        let input = form.querySelector(`input[name="${name}"]`);
        if (!input) {
            input = document.createElement("input");
            input.type = "hidden";
            input.name = name;
            form.appendChild(input);
        }
        input.value = value;
    }

    async function refreshCaptcha(widget) {
        const image = widget.querySelector("[data-captcha-image]");
        const id = widget.querySelector("[name=captcha_id]");
        const answer = widget.querySelector("[name=captcha_answer]");
        const button = widget.querySelector("[data-captcha-refresh]");
        if (!image || !id) return;
        id.value = "";
        if (answer) answer.value = "";
        if (button) button.disabled = true;
        try {
            const response = await fetch("/captcha", {credentials: "same-origin", cache: "no-store"});
            if (!response.ok) throw new Error("captcha unavailable");
            const data = await response.json();
            id.value = data.id;
            image.src = data.image_url;
            image.alt = "六位图片验证码，无法辨认时请换一张";
            showError(widget, "[data-captcha-error]", "");
        } catch (_) {
            image.removeAttribute("src");
            showError(widget, "[data-captcha-error]", "验证码加载失败，请稍后点击换一张。");
        } finally {
            if (button) button.disabled = false;
        }
    }

    async function initialize() {
        document.querySelectorAll("form[data-password-purpose]").forEach(form => {
            const password = form.querySelector("[data-password-field]");
            const confirm = form.querySelector("[data-password-confirm]");
            if (!password) return;
            // These inputs never have a submission name, even if scripts fail.
            password.removeAttribute("name");
            if (confirm) confirm.removeAttribute("name");
            let busy = false;
            form.addEventListener("submit", async event => {
                event.preventDefault();
                if (busy) return;
                showError(form, "[data-password-error]", "");
                if (confirm && password.value !== confirm.value) {
                    showError(form, "[data-password-error]", "两次输入的密码不一致。");
                    return;
                }
                if (!window.forge || !window.crypto || !window.crypto.getRandomValues) {
                    showError(form, "[data-password-error]", "浏览器无法完成安全加密，请使用最新版本的浏览器。");
                    return;
                }
                const value = password.value;
                const submitter = event.submitter;
                busy = true;
                if (submitter) submitter.disabled = true;
                try {
                    const passwordBytes = window.forge.util.encodeUtf8(value);
                    if (!passwordBytes.length || passwordBytes.length > 128) {
                        showError(form, "[data-password-error]", "密码不能为空，且不能超过 128 个 UTF-8 字节。");
                        return;
                    }
                    const response = await fetch(`/password-challenge?purpose=${encodeURIComponent(form.dataset.passwordPurpose)}`,
                        {credentials: "same-origin", cache: "no-store"});
                    if (!response.ok) throw new Error("challenge unavailable");
                    const challenge = await response.json();
                    if (challenge.algorithm !== "RSA-OAEP-SHA256") throw new Error("unsupported algorithm");
                    const key = window.forge.pki.publicKeyFromPem(challenge.public_key);
                    const payload = JSON.stringify({
                        password_b64: window.forge.util.encode64(passwordBytes),
                        nonce: challenge.nonce
                    });
                    // getRandomValues is available in HTTP contexts. Explicit
                    // OAEP seed prevents any fallback to weaker library entropy.
                    const seed = new Uint8Array(32);
                    window.crypto.getRandomValues(seed);
                    const ciphertext = key.encrypt(payload, "RSA-OAEP", {
                        md: window.forge.md.sha256.create(),
                        mgf1: {md: window.forge.md.sha256.create()},
                        seed: Array.from(seed, byte => String.fromCharCode(byte)).join("")
                    });
                    hidden(form, "password_challenge", challenge.id);
                    hidden(form, "password_envelope", window.forge.util.encode64(ciphertext));
                    if (submitter && submitter.name) hidden(form, submitter.name, submitter.value);
                    password.value = "";
                    if (confirm) confirm.value = "";
                    HTMLFormElement.prototype.submit.call(form);
                } catch (_) {
                    showError(form, "[data-password-error]", "密码加密失败或请求过于频繁，请稍后重试。");
                } finally {
                    busy = false;
                    if (submitter) submitter.disabled = false;
                }
            });
        });
        // Sequential first requests ensure multiple widgets share the same
        // newly established browser nonce instead of racing Set-Cookie values.
        for (const widget of document.querySelectorAll("[data-captcha-widget]")) {
            const button = widget.querySelector("[data-captcha-refresh]");
            if (button) button.addEventListener("click", () => refreshCaptcha(widget));
            await refreshCaptcha(widget);
        }
    }

    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", initialize);
    else initialize();
})();
