// Keeper JavaScript Functions

// Initialize tooltips and other Bootstrap components
document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Initialize popovers
    var popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    var popoverList = popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });
});

// Copy to clipboard functionality
function copyToClipboard(text, button) {
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(function() {
            showCopyFeedback(button);
        }).catch(function(err) {
            console.error('Failed to copy: ', err);
            fallbackCopyTextToClipboard(text, button);
        });
    } else {
        fallbackCopyTextToClipboard(text, button);
    }
}

function fallbackCopyTextToClipboard(text, button) {
    var textArea = document.createElement("textarea");
    textArea.value = text;
    textArea.style.top = "0";
    textArea.style.left = "0";
    textArea.style.position = "fixed";
    textArea.style.opacity = "0";
    
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    
    try {
        var successful = document.execCommand('copy');
        if (successful) {
            showCopyFeedback(button);
        }
    } catch (err) {
        console.error('Fallback: Could not copy text: ', err);
    }
    
    document.body.removeChild(textArea);
}

function showCopyFeedback(button) {
    if (button) {
        button.classList.add('copied');
        setTimeout(function() {
            button.classList.remove('copied');
        }, 1000);
    }
}

// Secret value visibility toggle
function toggleSecretVisibility(element, secretId) {
    var valueElement = document.getElementById('secret-value-' + secretId);
    var isVisible = !valueElement.classList.contains('masked');
    
    if (isVisible) {
        valueElement.classList.add('masked');
        element.innerHTML = '<i class="fas fa-eye"></i>';
        element.title = 'Show secret';
    } else {
        valueElement.classList.remove('masked');
        element.innerHTML = '<i class="fas fa-eye-slash"></i>';
        element.title = 'Hide secret';
    }
}

// Auto-hide alerts after 5 seconds
document.addEventListener('DOMContentLoaded', function() {
    var alerts = document.querySelectorAll('.alert.alert-dismissible');
    alerts.forEach(function(alert) {
        setTimeout(function() {
            var bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        }, 5000);
    });
});

// Form validation helpers
function validateEmail(email) {
    var re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
}

function validateUsername(username) {
    var re = /^[a-zA-Z0-9._-]+$/;
    return re.test(username) && username.length >= 3;
}

function validateSecretName(name) {
    var re = /^[a-zA-Z0-9._-]+$/;
    return re.test(name) && name.length >= 1;
}

// Password strength calculator
function calculatePasswordStrength(password) {
    var score = 0;
    var feedback = [];
    
    // Length check
    if (password.length >= 8) score += 1;
    else feedback.push('Use at least 8 characters');
    
    if (password.length >= 12) score += 1;
    if (password.length >= 16) score += 1;
    
    // Character variety
    if (/[a-z]/.test(password)) score += 1;
    else feedback.push('Add lowercase letters');
    
    if (/[A-Z]/.test(password)) score += 1;
    else feedback.push('Add uppercase letters');
    
    if (/[0-9]/.test(password)) score += 1;
    else feedback.push('Add numbers');
    
    if (/[^A-Za-z0-9]/.test(password)) score += 1;
    else feedback.push('Add symbols');
    
    // Common patterns
    if (/(.)\1{2,}/.test(password)) {
        score -= 1;
        feedback.push('Avoid repeated characters');
    }
    
    if (/123|abc|qwe/i.test(password)) {
        score -= 1;
        feedback.push('Avoid common patterns');
    }
    
    // Determine strength level
    var strength = 'very-weak';
    var color = 'danger';
    var text = 'Very Weak';
    
    if (score >= 7) {
        strength = 'very-strong';
        color = 'success';
        text = 'Very Strong';
    } else if (score >= 5) {
        strength = 'strong';
        color = 'info';
        text = 'Strong';
    } else if (score >= 3) {
        strength = 'medium';
        color = 'warning';
        text = 'Medium';
    } else if (score >= 1) {
        strength = 'weak';
        color = 'warning';
        text = 'Weak';
    }
    
    return {
        score: score,
        strength: strength,
        color: color,
        text: text,
        feedback: feedback
    };
}

// Real-time password strength indicator
function updatePasswordStrength(passwordField, indicatorElement) {
    var password = passwordField.value;
    if (!password) {
        indicatorElement.innerHTML = '';
        return;
    }
    
    var result = calculatePasswordStrength(password);
    var html = `
        <div class="password-strength mb-2">
            <div class="d-flex justify-content-between align-items-center mb-1">
                <small class="text-muted">Strength:</small>
                <small class="text-${result.color}">${result.text}</small>
            </div>
            <div class="strength-indicator strength-${result.strength}"></div>
        </div>
    `;
    
    if (result.feedback.length > 0) {
        html += `<small class="text-muted">${result.feedback.join(', ')}</small>`;
    }
    
    indicatorElement.innerHTML = html;
}

// AJAX helpers
function makeRequest(url, options = {}) {
    const defaultOptions = {
        method: 'GET',
        headers: {
            'Content-Type': 'application/json',
        },
        credentials: 'same-origin'
    };
    
    const config = Object.assign(defaultOptions, options);
    
    return fetch(url, config)
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        });
}

// Sync status checker
function checkSyncStatus(secretId, callback) {
    makeRequest(`/secrets/${secretId}/sync`)
        .then(data => {
            if (callback) callback(null, data);
        })
        .catch(error => {
            if (callback) callback(error, null);
        });
}

// Bulk operations helpers
function getSelectedSecrets() {
    var checkboxes = document.querySelectorAll('.secret-checkbox:checked');
    return Array.from(checkboxes).map(cb => cb.value);
}

function updateBulkActionButtons() {
    var selected = getSelectedSecrets();
    var bulkButtons = document.querySelectorAll('.bulk-action-btn');
    
    bulkButtons.forEach(function(btn) {
        btn.disabled = selected.length === 0;
    });
}

// Environment color helpers
function getEnvironmentColor(envName) {
    const colors = {
        'development': '#28a745',
        'staging': '#ffc107',
        'production': '#dc3545',
        'test': '#17a2b8'
    };
    return colors[envName] || '#6c757d';
}

// Format date/time helpers
function formatDateTime(dateString) {
    if (!dateString) return 'Never';
    
    const date = new Date(dateString);
    const now = new Date();
    const diff = now - date;
    
    // If less than 24 hours ago, show relative time
    if (diff < 24 * 60 * 60 * 1000) {
        const hours = Math.floor(diff / (60 * 60 * 1000));
        const minutes = Math.floor(diff / (60 * 1000));
        
        if (hours > 0) return `${hours} hour${hours > 1 ? 's' : ''} ago`;
        if (minutes > 0) return `${minutes} minute${minutes > 1 ? 's' : ''} ago`;
        return 'Just now';
    }
    
    // Otherwise show formatted date
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
}

// Secret type icon helpers
function getSecretTypeIcon(secretType) {
    const icons = {
        'string': 'fas fa-font',
        'password': 'fas fa-key',
        'api_key': 'fas fa-code',
        'ssh_key': 'fas fa-terminal',
        'rsa_key': 'fas fa-lock',
        'certificate': 'fas fa-certificate',
        'json': 'fas fa-brackets-curly',
        'yaml': 'fas fa-file-code'
    };
    return icons[secretType] || 'fas fa-file-text';
}

// Loading state helpers
function showLoading(element, text = 'Loading...') {
    if (element) {
        element.innerHTML = `
            <span class="spinner-border spinner-border-sm me-2" role="status"></span>
            ${text}
        `;
        element.disabled = true;
    }
}

function hideLoading(element, originalText) {
    if (element) {
        element.innerHTML = originalText;
        element.disabled = false;
    }
}

// Search and filter helpers
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Auto-save form data to localStorage
function autoSaveForm(formId, interval = 30000) {
    const form = document.getElementById(formId);
    if (!form) return;
    
    const saveKey = `keeper_autosave_${formId}`;
    
    // Save form data
    function saveFormData() {
        const formData = new FormData(form);
        const data = {};
        for (let [key, value] of formData.entries()) {
            data[key] = value;
        }
        localStorage.setItem(saveKey, JSON.stringify(data));
    }
    
    // Restore form data
    function restoreFormData() {
        const saved = localStorage.getItem(saveKey);
        if (saved) {
            try {
                const data = JSON.parse(saved);
                Object.keys(data).forEach(key => {
                    const field = form.querySelector(`[name="${key}"]`);
                    if (field) {
                        if (field.type === 'checkbox') {
                            field.checked = data[key] === 'on';
                        } else {
                            field.value = data[key];
                        }
                    }
                });
            } catch (e) {
                console.error('Error restoring form data:', e);
            }
        }
    }
    
    // Clear saved data
    function clearSavedData() {
        localStorage.removeItem(saveKey);
    }
    
    // Auto-save on input
    form.addEventListener('input', debounce(saveFormData, 1000));
    
    // Restore on page load
    restoreFormData();
    
    // Clear on successful submit
    form.addEventListener('submit', clearSavedData);
    
    return { save: saveFormData, restore: restoreFormData, clear: clearSavedData };
}

// Global error handler
window.addEventListener('error', function(e) {
    console.error('Global error:', e.error);
    // You could send this to a logging service
});

// Page visibility change handler (for refreshing data when tab becomes active)
document.addEventListener('visibilitychange', function() {
    if (!document.hidden) {
        // Page became visible, refresh data if needed
        var event = new CustomEvent('pageVisible');
        document.dispatchEvent(event);
    }
});

// Export functions for use in other scripts
window.Keeper = {
    copyToClipboard,
    toggleSecretVisibility,
    validateEmail,
    validateUsername,
    validateSecretName,
    calculatePasswordStrength,
    updatePasswordStrength,
    makeRequest,
    checkSyncStatus,
    getSelectedSecrets,
    updateBulkActionButtons,
    getEnvironmentColor,
    formatDateTime,
    getSecretTypeIcon,
    showLoading,
    hideLoading,
    debounce,
    autoSaveForm
};