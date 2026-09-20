function switchType(type) {
    document.getElementById('typeInput').value = type;
    document.querySelectorAll('.type-tab').forEach(t => t.classList.remove('active'));
    document.querySelector('[data-type="' + type + '"]').classList.add('active');

    if (type === 'letter') {
        document.getElementById('letterSection').style.display = '';
        document.getElementById('phoneSection').style.display = 'none';
        document.getElementById('submitBtn').textContent = '📨 寄出这封信';
        // 同步 title 字段
        document.querySelector('input[name="title"]').required = true;
        document.querySelector('textarea[name="content"]').required = true;
        document.getElementById('phoneInput').required = false;
        document.getElementById('phoneTitleInput').required = false;
        document.getElementById('preferredCallTimeInput').required = false;
    } else {
        document.getElementById('letterSection').style.display = 'none';
        document.getElementById('phoneSection').style.display = '';
        document.getElementById('submitBtn').textContent = '📞 提交来电登记';
        document.querySelector('input[name="title"]').required = false;
        document.querySelector('textarea[name="content"]').required = false;
        document.getElementById('phoneInput').required = true;
        document.getElementById('phoneTitleInput').required = true;
        document.getElementById('preferredCallTimeInput').required = true;
    }
}

// 提交前同步字段
document.getElementById('writeForm').addEventListener('submit', function() {
    var type = document.getElementById('typeInput').value;
    if (type === 'phone') {
        document.querySelector('input[name="title"]').value = document.getElementById('phoneTitleInput').value;
        document.querySelector('textarea[name="content"]').value = document.getElementById('phoneContentInput').value;
    }
});

switchType(document.getElementById('typeInput').value || 'letter');

document.querySelectorAll(".type-tab").forEach(tab => {
    tab.addEventListener("click", () => switchType(tab.dataset.type));
});
