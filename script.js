// Tab functionality with smooth animations
function showTab(tabName) {
    // Hide all tab contents with slide out animation
    const tabContents = document.querySelectorAll('.tab-content');
    tabContents.forEach(content => {
        if (content.classList.contains('active')) {
            content.style.animation = 'slideOutToLeft 0.3s ease-out forwards';
            setTimeout(() => {
                content.classList.remove('active');
                content.style.animation = '';
            }, 300);
        }
    });
    
    // Remove active class from all tab buttons
    const tabButtons = document.querySelectorAll('.tab-btn');
    tabButtons.forEach(btn => {
        btn.classList.remove('active');
        btn.style.transform = 'translateY(0)';
    });
    
    // Add active class to clicked button with animation
    event.target.classList.add('active');
    event.target.style.transform = 'translateY(-2px)';
    
    // Show selected tab content with slide in animation
    setTimeout(() => {
        const selectedTab = document.getElementById(tabName);
        selectedTab.classList.add('active');
        selectedTab.style.animation = 'slideInFromRight 0.6s ease-out forwards';
        
        // Add staggered animation to form elements
        if (tabName === 'vote') {
            animateFormElements();
        } else if (tabName === 'results') {
            animateResults();
        }
    }, 300);
}

// Animate form elements with staggered effect
function animateFormElements() {
    const formGroups = document.querySelectorAll('.form-group');
    formGroups.forEach((group, index) => {
        group.style.animation = 'none';
        setTimeout(() => {
            group.style.animation = `slideInFromLeft 0.6s ease-out ${index * 0.1}s both`;
        }, 100);
    });
    
    // Animate candidate cards
    const candidateCards = document.querySelectorAll('.candidate-card');
    candidateCards.forEach((card, index) => {
        card.style.animation = 'none';
        setTimeout(() => {
            card.style.animation = `slideInFromBottom 0.6s ease-out ${index * 0.2}s both`;
        }, 200);
    });
}

// Animate results with count up effect
function animateResults() {
    const resultCards = document.querySelectorAll('.result-card');
    resultCards.forEach((card, index) => {
        card.style.animation = 'none';
        setTimeout(() => {
            card.style.animation = `slideInFromBottom 0.6s ease-out ${index * 0.2}s both`;
        }, 100);
    });
    
    // Animate vote counts
    setTimeout(() => {
        animateVoteCounts();
    }, 800);
}

// Animate vote counts with count up effect
function animateVoteCounts() {
    const counts = document.querySelectorAll('.count');
    counts.forEach(count => {
        const finalValue = parseInt(count.textContent);
        animateCount(count, 0, finalValue, 1000);
    });
}

function animateCount(element, start, end, duration) {
    const startTime = performance.now();
    const difference = end - start;
    
    function updateCount(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        
        const current = Math.floor(start + (difference * progress));
        element.textContent = current;
        
        if (progress < 1) {
            requestAnimationFrame(updateCount);
        }
    }
    
    requestAnimationFrame(updateCount);
}

// Candidate selection with enhanced animation
function selectCandidate(candidateId) {
    // Remove selected class from all candidate cards with animation
    const candidateCards = document.querySelectorAll('.candidate-card');
    candidateCards.forEach(card => {
        if (card.classList.contains('selected')) {
            card.style.animation = 'deselectCard 0.3s ease-out forwards';
            setTimeout(() => {
                card.classList.remove('selected');
                card.style.animation = '';
            }, 300);
        }
    });
    
    // Add selected class to clicked card with animation
    const selectedCard = document.querySelector(`[onclick="selectCandidate('${candidateId}')"]`);
    setTimeout(() => {
        selectedCard.classList.add('selected');
        selectedCard.style.animation = 'selectCard 0.4s ease-out forwards';
        
        // Add ripple effect
        addRippleEffect(selectedCard);
    }, 300);
    
    // Check the radio button
    document.getElementById(candidateId).checked = true;
}

// Add ripple effect to candidate cards
function addRippleEffect(element) {
    const ripple = document.createElement('div');
    ripple.style.cssText = `
        position: absolute;
        border-radius: 50%;
        background: rgba(255, 255, 255, 0.6);
        transform: scale(0);
        animation: ripple 0.6s linear;
        pointer-events: none;
        top: 50%;
        left: 50%;
        width: 100px;
        height: 100px;
        margin: -50px 0 0 -50px;
    `;
    
    element.style.position = 'relative';
    element.appendChild(ripple);
    
    setTimeout(() => {
        ripple.remove();
    }, 600);
}

// Form validation with enhanced feedback
function validateVoterId(voterId) {
    const pattern = /^[A-Z0-9]{8,12}$/;
    return pattern.test(voterId);
}

function validateName(name) {
    const pattern = /^[A-Za-z\s]{3,50}$/;
    return pattern.test(name);
}

function validateEmail(email) {
    const pattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return pattern.test(email);
}

// Real-time validation with smooth animations
document.getElementById('voterId').addEventListener('input', function() {
    const voterId = this.value;
    const errorElement = document.getElementById('voterIdError');
    
    if (voterId && !validateVoterId(voterId)) {
        errorElement.textContent = 'Voter ID must be 8-12 characters (letters and numbers only)';
        this.style.borderColor = '#e74c3c';
        this.style.animation = 'shake 0.5s ease-in-out';
    } else {
        errorElement.textContent = '';
        this.style.borderColor = '#e1e5e9';
        this.style.animation = 'successPulse 0.3s ease-out';
    }
});

document.getElementById('voterName').addEventListener('input', function() {
    const name = this.value;
    const errorElement = document.getElementById('voterNameError');
    
    if (name && !validateName(name)) {
        errorElement.textContent = 'Name must be 3-50 characters (letters and spaces only)';
        this.style.borderColor = '#e74c3c';
        this.style.animation = 'shake 0.5s ease-in-out';
    } else {
        errorElement.textContent = '';
        this.style.borderColor = '#e1e5e9';
        this.style.animation = 'successPulse 0.3s ease-out';
    }
});

document.getElementById('voterEmail').addEventListener('input', function() {
    const email = this.value;
    const errorElement = document.getElementById('voterEmailError');
    
    if (email && !validateEmail(email)) {
        errorElement.textContent = 'Please enter a valid email address';
        this.style.borderColor = '#e74c3c';
        this.style.animation = 'shake 0.5s ease-in-out';
    } else {
        errorElement.textContent = '';
        this.style.borderColor = '#e1e5e9';
        this.style.animation = 'successPulse 0.3s ease-out';
    }
});

// Vote form submission with enhanced animations
document.getElementById('voteForm').addEventListener('submit', function(e) {
    e.preventDefault();
    
    const voterId = document.getElementById('voterId').value;
    const voterName = document.getElementById('voterName').value;
    const voterEmail = document.getElementById('voterEmail').value;
    const constituency = document.getElementById('constituency').value;
    const candidate = document.querySelector('input[name="candidate"]:checked');
    const confirmVote = document.getElementById('confirmVote').checked;
    
    // Validation with enhanced feedback
    if (!validateVoterId(voterId)) {
        showValidationError('Please enter a valid Voter ID');
        return;
    }
    
    if (!validateName(voterName)) {
        showValidationError('Please enter a valid name');
        return;
    }
    
    if (!validateEmail(voterEmail)) {
        showValidationError('Please enter a valid email address');
        return;
    }
    
    if (!constituency) {
        showValidationError('Please select your constituency');
        return;
    }
    
    if (!candidate) {
        showValidationError('Please select a candidate');
        return;
    }
    
    if (!confirmVote) {
        showValidationError('Please confirm your vote');
        return;
    }
    
    // Show loading state with animation
    const submitBtn = this.querySelector('.submit-btn');
    const originalText = submitBtn.innerHTML;
    submitBtn.innerHTML = '<span class="loading"></span> Submitting...';
    submitBtn.disabled = true;
    submitBtn.style.animation = 'pulse 1s infinite';
    
    // Simulate API call (replace with actual backend call)
    setTimeout(() => {
        // TODO: Send data to backend
        const voteData = {
            voterId: voterId,
            voterName: voterName,
            voterEmail: voterEmail,
            constituency: constituency,
            candidate: candidate.value,
            timestamp: new Date().toISOString()
        };
        
        console.log('Vote submitted:', voteData);
        
        // Update results (simulate)
        updateResults();
        
        // Show success message with animation
        showSuccessMessage(`✅ Vote submitted successfully!\n\nVoter ID: ${voterId}\nCandidate: ${candidate.value}\nConstituency: ${constituency}\n\nYour vote has been recorded securely.`);
        
        // Reset form with animation
        resetFormWithAnimation(this);
        
        // Reset button
        submitBtn.innerHTML = originalText;
        submitBtn.disabled = false;
        submitBtn.style.animation = '';
        
    }, 2000);
});

// Show validation error with animation
function showValidationError(message) {
    const errorDiv = document.createElement('div');
    errorDiv.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: #e74c3c;
        color: white;
        padding: 15px 20px;
        border-radius: 8px;
        box-shadow: 0 4px 15px rgba(231, 76, 60, 0.3);
        z-index: 1000;
        animation: slideInFromRight 0.3s ease-out;
    `;
    errorDiv.textContent = message;
    
    document.body.appendChild(errorDiv);
    
    setTimeout(() => {
        errorDiv.style.animation = 'slideOutToRight 0.3s ease-out forwards';
        setTimeout(() => {
            errorDiv.remove();
        }, 300);
    }, 3000);
}

// Show success message with animation
function showSuccessMessage(message) {
    const successDiv = document.createElement('div');
    successDiv.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: #27ae60;
        color: white;
        padding: 15px 20px;
        border-radius: 8px;
        box-shadow: 0 4px 15px rgba(39, 174, 96, 0.3);
        z-index: 1000;
        animation: slideInFromRight 0.3s ease-out;
    `;
    successDiv.textContent = message;
    
    document.body.appendChild(successDiv);
    
    setTimeout(() => {
        successDiv.style.animation = 'slideOutToRight 0.3s ease-out forwards';
        setTimeout(() => {
            successDiv.remove();
        }, 300);
    }, 4000);
}

// Reset form with animation
function resetFormWithAnimation(form) {
    const formGroups = form.querySelectorAll('.form-group');
    formGroups.forEach((group, index) => {
        setTimeout(() => {
            group.style.animation = 'fadeOut 0.3s ease-out forwards';
            setTimeout(() => {
                group.style.animation = 'fadeIn 0.3s ease-out forwards';
            }, 300);
        }, index * 100);
    });
    
    setTimeout(() => {
        form.reset();
        document.querySelectorAll('.candidate-card').forEach(card => {
            card.classList.remove('selected');
        });
    }, formGroups.length * 100 + 300);
}

// Verification form submission with enhanced animations
document.getElementById('verifyForm').addEventListener('submit', function(e) {
    e.preventDefault();
    
    const verifyVoterId = document.getElementById('verifyVoterId').value;
    const resultDiv = document.getElementById('verificationResult');
    
    if (!validateVoterId(verifyVoterId)) {
        resultDiv.innerHTML = '<span style="color: #e74c3c;">❌ Please enter a valid Voter ID</span>';
        resultDiv.style.animation = 'shake 0.5s ease-in-out';
        return;
    }
    
    // Show loading with animation
    resultDiv.innerHTML = '<span class="loading"></span> Verifying your vote...';
    resultDiv.style.animation = 'pulse 1s infinite';
    
    // Simulate verification (replace with actual backend call)
    setTimeout(() => {
        // TODO: Send verification request to backend
        const isVerified = Math.random() > 0.3; // Simulate verification result
        
        resultDiv.style.animation = '';
        
        if (isVerified) {
            const candidates = ['Rahul Sharma (Indian National Party)', 'Priya Patel (Democratic Alliance)', 'Amit Kumar (People\'s Front)'];
            const randomCandidate = candidates[Math.floor(Math.random() * candidates.length)];
            const randomConstituency = ['North Delhi', 'South Delhi', 'East Delhi', 'West Delhi', 'Central Delhi'][Math.floor(Math.random() * 5)];
            
            resultDiv.innerHTML = `
                <div style="color: #27ae60; padding: 15px; background: #d5f4e6; border-radius: 8px; border: 1px solid #27ae60; animation: slideInFromTop 0.6s ease-out;">
                    <h3>✅ Vote Verified Successfully!</h3>
                    <p><strong>Voter ID:</strong> ${verifyVoterId}</p>
                    <p><strong>Voted For:</strong> ${randomCandidate}</p>
                    <p><strong>Constituency:</strong> ${randomConstituency}</p>
                    <p><strong>Vote Hash:</strong> <code>${generateHash(verifyVoterId)}</code></p>
                    <p><small>Your vote is securely stored and verifiable.</small></p>
                </div>
            `;
        } else {
            resultDiv.innerHTML = `
                <div style="color: #e74c3c; padding: 15px; background: #fdf2f2; border-radius: 8px; border: 1px solid #e74c3c; animation: slideInFromTop 0.6s ease-out;">
                    <h3>❌ Vote Not Found</h3>
                    <p>No vote found for Voter ID: ${verifyVoterId}</p>
                    <p><small>Please check your Voter ID or contact support if you believe this is an error.</small></p>
                </div>
            `;
        }
    }, 1500);
    
    this.reset();
});

// Generate dummy hash for verification
function generateHash(text) {
    let hash = 0;
    for (let i = 0; i < text.length; i++) {
        const char = text.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash; // Convert to 32-bit integer
    }
    return Math.abs(hash).toString(16).padStart(8, '0');
}

// Update live results with smooth animations
function updateResults() {
    const votes1 = parseInt(document.getElementById('votes1').textContent) + Math.floor(Math.random() * 3) + 1;
    const votes2 = parseInt(document.getElementById('votes2').textContent) + Math.floor(Math.random() * 3) + 1;
    const votes3 = parseInt(document.getElementById('votes3').textContent) + Math.floor(Math.random() * 3) + 1;
    
    const total = votes1 + votes2 + votes3;
    
    // Animate vote count updates
    animateCount(document.getElementById('votes1'), parseInt(document.getElementById('votes1').textContent), votes1, 800);
    animateCount(document.getElementById('votes2'), parseInt(document.getElementById('votes2').textContent), votes2, 800);
    animateCount(document.getElementById('votes3'), parseInt(document.getElementById('votes3').textContent), votes3, 800);
    animateCount(document.getElementById('totalVotes'), parseInt(document.getElementById('totalVotes').textContent), total, 800);
    
    // Update percentages with animation
    setTimeout(() => {
        document.getElementById('percent1').textContent = Math.round((votes1 / total) * 100) + '%';
        document.getElementById('percent2').textContent = Math.round((votes2 / total) * 100) + '%';
        document.getElementById('percent3').textContent = Math.round((votes3 / total) * 100) + '%';
        
        // Animate progress bars
        document.getElementById('progress1').style.width = (votes1 / total) * 100 + '%';
        document.getElementById('progress2').style.width = (votes2 / total) * 100 + '%';
        document.getElementById('progress3').style.width = (votes3 / total) * 100 + '%';
    }, 800);
}

// Initialize results with some dummy data and animations
document.addEventListener('DOMContentLoaded', function() {
    // Set initial results
    document.getElementById('votes1').textContent = '45';
    document.getElementById('votes2').textContent = '38';
    document.getElementById('votes3').textContent = '27';
    document.getElementById('totalVotes').textContent = '110';
    
    // Animate initial load
    setTimeout(() => {
        updateResults();
        animateFormElements();
    }, 500);
    
    // Auto-update results every 30 seconds
    setInterval(updateResults, 30000);
    
    // Add scroll animations
    addScrollAnimations();
});

// Add scroll animations for elements
function addScrollAnimations() {
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    };
    
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.style.animation = 'slideInFromBottom 0.6s ease-out forwards';
            }
        });
    }, observerOptions);
    
    // Observe elements for scroll animation
    document.querySelectorAll('.form-container, .results-container, .candidate-card, .result-card').forEach(el => {
        observer.observe(el);
    });
}

// Add smooth scrolling for better UX
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        document.querySelector(this.getAttribute('href')).scrollIntoView({
            behavior: 'smooth'
        });
    });
});

// Add CSS animations dynamically
const style = document.createElement('style');
style.textContent = `
    @keyframes slideOutToLeft {
        from { transform: translateX(0); opacity: 1; }
        to { transform: translateX(-100%); opacity: 0; }
    }
    
    @keyframes slideOutToRight {
        from { transform: translateX(0); opacity: 1; }
        to { transform: translateX(100%); opacity: 0; }
    }
    
    @keyframes selectCard {
        0% { transform: translateY(0) scale(1); }
        50% { transform: translateY(-10px) scale(1.05); }
        100% { transform: translateY(-5px) scale(1.05); }
    }
    
    @keyframes deselectCard {
        0% { transform: translateY(-5px) scale(1.05); }
        100% { transform: translateY(0) scale(1); }
    }
    
    @keyframes ripple {
        0% { transform: scale(0); opacity: 1; }
        100% { transform: scale(4); opacity: 0; }
    }
    
    @keyframes fadeOut {
        from { opacity: 1; transform: scale(1); }
        to { opacity: 0; transform: scale(0.95); }
    }
    
    @keyframes fadeIn {
        from { opacity: 0; transform: scale(0.95); }
        to { opacity: 1; transform: scale(1); }
    }
`;
document.head.appendChild(style); 