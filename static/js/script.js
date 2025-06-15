// Mobile menu functionality
document.addEventListener('DOMContentLoaded', function() {
    const mobileMenu = document.getElementById('mobileMenu');
    const navLinks = document.querySelector('.nav-links');
    
    if (mobileMenu && navLinks) {
        mobileMenu.addEventListener('click', function() {
            navLinks.classList.toggle('mobile-active');
            mobileMenu.classList.toggle('active');
        });
        
        // Close mobile menu when clicking on links
        document.querySelectorAll('.nav-links a').forEach(link => {
            link.addEventListener('click', () => {
                navLinks.classList.remove('mobile-active');
                mobileMenu.classList.remove('active');
            });
        });
    }
});

// Smooth scrolling for anchor links
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function(e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({
                behavior: 'smooth',
                block: 'start'
            });
        }
    });
});

// Newsletter form handling
document.getElementById('newsletterForm').addEventListener('submit', function(e) {
    e.preventDefault();
    
    const formData = new FormData();
    const emailInput = this.querySelector('.newsletter-input');
    const submitButton = this.querySelector('.newsletter-btn');
    const originalButtonText = submitButton.textContent;
    
    // Validate email
    if (!emailInput.value.trim()) {
        showNotification('Please enter your email address.', 'error');
        return;
    }
    
    if (!isValidEmail(emailInput.value.trim())) {
        showNotification('Please enter a valid email address.', 'error');
        return;
    }
    
    formData.append('email', emailInput.value.trim());
    
    // Update button state
    submitButton.textContent = 'Subscribing...';
    submitButton.disabled = true;
    
    fetch('/newsletter', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showNotification(data.message, 'success');
            emailInput.value = '';
        } else {
            showNotification(data.message, 'error');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showNotification('An error occurred. Please try again.', 'error');
    })
    .finally(() => {
        submitButton.textContent = originalButtonText;
        submitButton.disabled = false;
    });
});

// Contact form handling
document.getElementById('contactForm').addEventListener('submit', function(e) {
    e.preventDefault();
    
    const formData = new FormData(this);
    const submitButton = this.querySelector('button[type="submit"]');
    const originalButtonText = submitButton.textContent;
    
    // Validate required fields
    const requiredFields = ['name', 'email', 'phone', 'service'];
    let isValid = true;
    
    requiredFields.forEach(fieldName => {
        const field = this.querySelector(`[name="${fieldName}"]`);
        if (!field.value.trim()) {
            field.style.borderColor = '#ef4444';
            isValid = false;
        } else {
            field.style.borderColor = '';
        }
    });
    
    // Validate email format
    const emailField = this.querySelector('[name="email"]');
    if (emailField.value.trim() && !isValidEmail(emailField.value.trim())) {
        emailField.style.borderColor = '#ef4444';
        showNotification('Please enter a valid email address.', 'error');
        return;
    }
    
    if (!isValid) {
        showNotification('Please fill in all required fields.', 'error');
        return;
    }
    
    // Update button state
    submitButton.textContent = 'Sending Request...';
    submitButton.disabled = true;
    
    fetch('/contact', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showNotification(data.message, 'success');
            this.reset();
            
            // Update file upload label
            const fileLabel = this.querySelector('.file-upload-label');
            if (fileLabel) {
                fileLabel.textContent = '📷 Click to upload photos of the space (helps us provide accurate quotes)';
            }
        } else {
            showNotification(data.message, 'error');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showNotification('An error occurred. Please try again or call us directly at +44 7479 691603.', 'error');
    })
    .finally(() => {
        submitButton.textContent = originalButtonText;
        submitButton.disabled = false;
    });
});

// Comment form handling
document.getElementById('commentForm').addEventListener('submit', function(e) {
    e.preventDefault();
    
    const formData = new FormData(this);
    const submitButton = this.querySelector('button[type="submit"]');
    const originalButtonText = submitButton.textContent;
    
    // Validate required fields
    const requiredFields = ['name', 'email', 'rating', 'comment'];
    let isValid = true;
    
    requiredFields.forEach(fieldName => {
        const field = this.querySelector(`[name="${fieldName}"]`);
        if (!field.value.trim()) {
            field.style.borderColor = '#ef4444';
            isValid = false;
        } else {
            field.style.borderColor = '';
        }
    });
    
    // Validate email format
    const emailField = this.querySelector('[name="email"]');
    if (emailField.value.trim() && !isValidEmail(emailField.value.trim())) {
        emailField.style.borderColor = '#ef4444';
        showNotification('Please enter a valid email address.', 'error');
        return;
    }
    
    // Validate rating
    const ratingField = this.querySelector('[name="rating"]');
    const ratingValue = parseInt(ratingField.value);
    if (isNaN(ratingValue) || ratingValue < 1 || ratingValue > 5) {
        ratingField.style.borderColor = '#ef4444';
        showNotification('Please select a valid rating between 1 and 5.', 'error');
        return;
    }
    
    if (!isValid) {
        showNotification('Please fill in all required fields.', 'error');
        return;
    }
    
    // Update button state
    submitButton.textContent = 'Submitting...';
    submitButton.disabled = true;
    
    fetch('/comments', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showNotification(data.message, 'success');
            this.reset();
        } else {
            showNotification(data.message, 'error');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showNotification('An error occurred. Please try again.', 'error');
    })
    .finally(() => {
        submitButton.textContent = originalButtonText;
        submitButton.disabled = false;
    });
});

// File upload handling
document.getElementById('attachment').addEventListener('change', function() {
    const files = this.files;
    const label = document.querySelector('.file-upload-label');
    
    if (files.length === 0) {
        label.textContent = '📷 Click to upload photos of the space (helps us provide accurate quotes)';
    } else if (files.length === 1) {
        label.textContent = `📷 Selected: ${files[0].name}`;
    } else {
        label.textContent = `📷 Selected: ${files.length} files`;
    }
    
    // Validate file sizes
    const maxSize = 16 * 1024 * 1024; // 16MB
    for (let file of files) {
        if (file.size > maxSize) {
            showNotification(`File "${file.name}" is too large. Maximum size is 16MB.`, 'error');
            this.value = '';
            label.textContent = '📷 Click to upload photos of the space (helps us provide accurate quotes)';
            return;
        }
    }
});

// Utility functions
function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

function showNotification(message, type) {
    // Remove any existing notifications
    const existingNotification = document.querySelector('.notification');
    if (existingNotification) {
        existingNotification.remove();
    }
    
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.innerHTML = `
        <div class="notification-content">
            <span class="notification-icon">${type === 'success' ? '✅' : '❌'}</span>
            <span class="notification-message">${message}</span>
            <button class="notification-close">×</button>
        </div>
    `;
    
    // Add styles
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        z-index: 1000;
        max-width: 400px;
        padding: 0;
        border-radius: 10px;
        box-shadow: 0 4px 20px rgba(0,0,0,0.15);
        background: ${type === 'success' ? '#10b981' : '#ef4444'};
        color: white;
        font-family: inherit;
        animation: slideInRight 0.3s ease-out;
    `;
    
    const content = notification.querySelector('.notification-content');
    content.style.cssText = `
        display: flex;
        align-items: center;
        gap: 10px;
        padding: 15px 20px;
    `;
    
    const closeBtn = notification.querySelector('.notification-close');
    closeBtn.style.cssText = `
        background: rgba(255,255,255,0.2);
        border: none;
        color: white;
        cursor: pointer;
        border-radius: 50%;
        width: 25px;
        height: 25px;
        display: flex;
        align-items: center;
        justify-content: center;
        margin-left: auto;
        font-size: 18px;
        line-height: 1;
    `;
    
    // Add animation keyframes
    if (!document.querySelector('#notification-styles')) {
        const style = document.createElement('style');
        style.id = 'notification-styles';
        style.textContent = `
            @keyframes slideInRight {
                from {
                    transform: translateX(100%);
                    opacity: 0;
                }
                to {
                    transform: translateX(0);
                    opacity: 1;
                }
            }
            @keyframes slideOutRight {
                from {
                    transform: translateX(0);
                    opacity: 1;
                }
                to {
                    transform: translateX(100%);
                    opacity: 0;
                }
            }
        `;
        document.head.appendChild(style);
    }
    
    // Add close functionality
    closeBtn.addEventListener('click', () => {
        notification.style.animation = 'slideOutRight 0.3s ease-in';
        setTimeout(() => notification.remove(), 300);
    });
    
    // Add to page
    document.body.appendChild(notification);
    
    // Auto-remove after 6 seconds
    setTimeout(() => {
        if (notification.parentNode) {
            notification.style.animation = 'slideOutRight 0.3s ease-in';
            setTimeout(() => notification.remove(), 300);
        }
    }, 6000);
}

// Add some CSS for hover effects and transitions
const style = document.createElement('style');
style.textContent = `
    .form-group input,
    .form-group select,
    .form-group textarea {
        transition: border-color 0.3s ease, box-shadow 0.3s ease;
    }
    
    .form-group input:focus,
    .form-group select:focus,
    .form-group textarea:focus {
        outline: none;
        border-color: #2563eb;
        box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.1);
    }
    
    .btn-primary:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 20px rgba(0,0,0,0.15);
    }
    
    .btn-primary:disabled {
        opacity: 0.7;
        cursor: not-allowed;
        transform: none;
    }
    
    .file-upload-label:hover {
        background-color: #f3f4f6;
        border-color: #2563eb;
    }
    
    .social-link:hover {
        transform: scale(1.1);
    }
    
    .fab {
        position: fixed;
        bottom: 20px;
        right: 20px;
        width: 60px;
        height: 60px;
        background: linear-gradient(135deg, #2563eb, #1d4ed8);
        color: white;
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        text-decoration: none;
        font-size: 24px;
        box-shadow: 0 4px 20px rgba(37, 99, 235, 0.3);
        transition: all 0.3s ease;
        z-index: 1000;
    }
    
    .fab:hover {
        transform: scale(1.1);
        box-shadow: 0 6px 30px rgba(37, 99, 235, 0.4);
    }
    
    @media (max-width: 768px) {
        .fab {
            bottom: 15px;
            right: 15px;
            width: 50px;
            height: 50px;
            font-size: 20px;
        }
        
        .notification {
            left: 20px;
            right: 20px;
            max-width: none;
        }
    }
`;
document.head.appendChild(style);

// Stats
fetch('/api/stats')
    .then(res => res.json())
    .then(stats => {
        const mapping = {
            jobs_completed: '💼',
            customer_satisfaction: '⭐',
            monthly_bookings: '📅',
            areas_served: '📍',
            years_experience: '🏆',
            newsletter_subscribers: '📧'
        };

        const statsGrid = document.getElementById('statsGrid');
        statsGrid.innerHTML = '';

        Object.keys(mapping).forEach(key => {
            const value = stats[key] || 0;
            const label = key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
            const icon = mapping[key];

            const div = document.createElement('div');
            div.className = 'stat-item';
            div.innerHTML = `
                <div class="stat-icon">${icon}</div>
                <div class="stat-value">${value}</div>
                <div class="stat-label">${label}</div>
            `;
            statsGrid.appendChild(div);
        });

        document.getElementById('lastUpdated').textContent = 'Stats updated just now';
    });

// Stats Chart
fetch('/api/stats')
    .then(res => res.json())
    .then(data => {
        const ctx = document.getElementById('statsChart').getContext('2d');
        new Chart(ctx, {
            type: 'bar',
            data: {
                labels: Object.keys(data).map(k => k.replace(/_/g, ' ')),
                datasets: [{
                    label: 'Live Stats',
                    data: Object.values(data),
                    backgroundColor: '#3b82f6'
                }]
            },
            options: {
                responsive: true,
                scales: { y: { beginAtZero: true } }
            }
        });
        document.getElementById('lastUpdated').textContent = 'Stats updated just now';
    });

// Comments
fetch('/api/comments')
    .then(res => res.json())
    .then(comments => {
        const container = document.getElementById('commentsContainer');
        container.innerHTML = '';
        if (comments.length === 0) {
            container.innerHTML = '<p>No reviews yet. Be the first to share your experience!</p>';
        } else {
            comments.forEach(c => {
                const div = document.createElement('div');
                div.className = 'testimonial';
                div.innerHTML = `
                    <div class="testimonial-stars">${'★'.repeat(c.rating)}</div>
                    <p class="testimonial-text">"${c.comment}"</p>
                    <div class="testimonial-author">- ${c.name}</div>
                `;
                container.appendChild(div);
            });
        }
    });