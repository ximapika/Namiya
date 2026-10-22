(() => {
    "use strict";
    document.querySelectorAll("form[data-email-purpose]").forEach(form => {
        const button = form.querySelector("[data-send-email-code]");
        const status = form.querySelector("[data-email-status]");
        const challenge = form.querySelector("[name=email_challenge]");
        const email = form.querySelector("[name=email]");
        const code = form.querySelector("[name=email_code]");
        const username = form.querySelector("[name=username]");
        let waiting = false;
        function invalidate() { challenge.value = ""; code.value = ""; status.textContent = ""; }
        email.addEventListener("input", invalidate);
        if (username && form.dataset.emailPurpose === "reset") username.addEventListener("input", invalidate);
        button.addEventListener("click", async () => {
            if (waiting || !email.reportValidity()) return;
            const answer = form.querySelector("[name=captcha_answer]");
            if (!answer.value.trim()) { status.textContent = "请先填写图片验证码。"; answer.focus(); return; }
            if (username && !username.reportValidity()) return;
            waiting = true;
            button.disabled = true;
            status.textContent = "正在发送……";
            const fields = new URLSearchParams({purpose: form.dataset.emailPurpose});
            ["csrf_token", "email", "username", "captcha_id", "captcha_answer"].forEach(name => {
                const field = form.querySelector(`[name="${name}"]`);
                if (field) fields.set(name, field.value);
            });
            let cooldown = 0;
            try {
                const response = await fetch("/email-code", {method: "POST", credentials: "same-origin", body: fields});
                const payload = await response.json();
                status.textContent = payload.message || "发送失败，请稍后再试。";
                if (response.ok) { challenge.value = payload.id; cooldown = Number(payload.resend_after) || 60; }
            } catch (_) { status.textContent = "邮件暂时无法发送，请稍后再试。"; }
            finally {
                form.querySelector("[data-captcha-refresh]").click();
                if (cooldown > 0) {
                    button.textContent = `${cooldown} 秒后重发`;
                    const timer = window.setInterval(() => {
                        cooldown -= 1;
                        button.textContent = cooldown > 0 ? `${cooldown} 秒后重发` : "发送验证码";
                        if (cooldown <= 0) { window.clearInterval(timer); waiting = false; button.disabled = false; }
                    }, 1000);
                } else { waiting = false; button.disabled = false; }
            }
        });
    });
})();
