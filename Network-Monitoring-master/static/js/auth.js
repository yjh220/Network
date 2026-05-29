// 认证相关JavaScript

// 切换密码可见性
document.addEventListener('DOMContentLoaded', function() {
    const togglePassword = document.getElementById('togglePassword');
    if (togglePassword) {
        togglePassword.addEventListener('click', function() {
            const passwordInput = this.previousElementSibling;
            const icon = this.querySelector('i');

            if (passwordInput.type === 'password') {
                passwordInput.type = 'text';
                icon.classList.remove('fa-eye');
                icon.classList.add('fa-eye-slash');
            } else {
                passwordInput.type = 'password';
                icon.classList.remove('fa-eye-slash');
                icon.classList.add('fa-eye');
            }
        });
    }

    // 表单验证增强
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function(e) {
            const submitBtn = form.querySelector('button[type="submit"]');
            if (submitBtn) {
                submitBtn.disabled = true;
                submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>处理中...';
            }
        });
    });

    // 自动关闭警告消息
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(alert => {
        setTimeout(() => {
            if (alert.classList.contains('show')) {
                const bsAlert = new bootstrap.Alert(alert);
                bsAlert.close();
            }
        }, 5000);
    });
});

// 键盘快捷键
document.addEventListener('keydown', function(e) {
    // ESC键清空输入框
    if (e.key === 'Escape') {
        const activeElement = document.activeElement;
        if (activeElement.tagName === 'INPUT') {
            activeElement.value = '';
        }
    }

    // Enter键提交表单（在密码输入框中）
    if (e.key === 'Enter') {
        const activeElement = document.activeElement;
        if (activeElement.type === 'password') {
            const form = activeElement.closest('form');
            if (form) {
                form.submit();
            }
        }
    }
});

// 用户名自动格式化
function formatUsername(input) {
    // 移除特殊字符，只保留字母、数字和下划线
    input.value = input.value.replace(/[^a-zA-Z0-9_]/g, '').toLowerCase();
}

// 密码强度检查
function checkPasswordStrength(password) {
    let strength = 0;

    if (password.length >= 8) strength += 1;
    if (password.length >= 12) strength += 1;
    if (/[a-z]/.test(password) && /[A-Z]/.test(password)) strength += 1;
    if (/\d/.test(password)) strength += 1;
    if (/[^a-zA-Z0-9]/.test(password)) strength += 1;

    return strength;
}

// 显示密码强度
function showPasswordStrength(password, elementId) {
    const strengthElement = document.getElementById(elementId);
    if (!strengthElement) return;

    const strength = checkPasswordStrength(password);
    const levels = ['很弱', '弱', '一般', '强', '很强'];
    const colors = ['#dc3545', '#fd7e14', '#ffc107', '#20c997', '#28a745'];

    strengthElement.textContent = levels[strength];
    strengthElement.style.color = colors[strength];
}

// 防止表单重复提交
function preventFormResubmission(form) {
    let submitted = false;

    form.addEventListener('submit', function(e) {
        // 如果已经在提交中，阻止重复提交
        if (submitted) {
            e.preventDefault();
            return false;
        }

        // 检查表单验证
        if (!form.checkValidity()) {
            e.preventDefault();
            e.stopPropagation();
            return false;
        }

        submitted = true;

        // 提交后5秒重置状态
        setTimeout(() => {
            submitted = false;
        }, 5000);
    });
}

// 初始化所有表单的防重复提交
document.addEventListener('DOMContentLoaded', function() {
    const forms = document.querySelectorAll('form');
    forms.forEach(preventFormResubmission);
});
