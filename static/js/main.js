function copyToClipboard(button, textSelector) {
    const container = button.closest('.group');
    const targetElement = container.querySelector(textSelector);
    const textToCopy = targetElement.textContent || targetElement.innerText;
    
    navigator.clipboard.writeText(textToCopy.trim()).then(() => {
        const originalText = button.innerText;
        button.innerText = 'COPIED!';
        button.classList.add('!text-green-500', '!border-green-500');
        
        setTimeout(() => {
            button.innerText = originalText;
            button.classList.remove('!text-green-500', '!border-green-500');
        }, 2000);
    }).catch(err => {
        console.error('Failed to copy: ', err);
        button.innerText = 'ERROR';
        setTimeout(() => {
            button.innerText = 'COPY';
        }, 2000);
    });
}

class PaginatedGrid {
    constructor(config) {
        this.searchInput = config.searchInput;
        this.items = config.items;
        this.fuseInstance = config.fuseInstance;
        this.itemsPerPage = config.itemsPerPage || 12;
        this.paginationControls = config.paginationControls;
        this.prevButton = config.prevButton;
        this.nextButton = config.nextButton;
        this.pageInfo = config.pageInfo;
        this.datasetKey = config.datasetKey;

        this.currentPage = 1;
        this.filteredItems = [...this.items];

        this.init();
    }

    init() {
        if (this.prevButton && this.nextButton) {
            this.prevButton.addEventListener('click', () => {
                if (this.currentPage > 1) {
                    this.currentPage--;
                    this.update();
                    window.scrollTo({ top: 0, behavior: 'smooth' });
                }
            });

            this.nextButton.addEventListener('click', () => {
                const totalPages = Math.ceil(this.filteredItems.length / this.itemsPerPage);
                if (this.currentPage < totalPages) {
                    this.currentPage++;
                    this.update();
                    window.scrollTo({ top: 0, behavior: 'smooth' });
                }
            });
        }

        if (this.searchInput) {
            this.searchInput.addEventListener('input', (e) => {
                const query = e.target.value;
                if (!query) {
                    this.filteredItems = [...this.items];
                } else {
                    const results = this.fuseInstance.search(query);
                    const matchedNames = new Set(results.map(r => r.item.name));
                    this.filteredItems = this.items.filter(card => matchedNames.has(card.dataset[this.datasetKey]));
                }
                this.currentPage = 1;
                this.update();
            });
        }

        this.update();
    }

    update() {
        const totalPages = Math.ceil(this.filteredItems.length / this.itemsPerPage);
        
        if (totalPages <= 1) {
            if (this.paginationControls) {
                this.paginationControls.classList.add('hidden');
                this.paginationControls.classList.remove('flex');
            }
        } else {
            if (this.paginationControls) {
                this.paginationControls.classList.remove('hidden');
                this.paginationControls.classList.add('flex');
            }
        }

        if (this.currentPage > totalPages) this.currentPage = totalPages || 1;

        if (this.pageInfo) {
            this.pageInfo.textContent = `Page ${this.currentPage} of ${totalPages || 1}`;
            this.pageInfo.setAttribute('aria-label', `Page ${this.currentPage} of ${totalPages || 1}`);
        }
        
        if (this.prevButton && this.nextButton) {
            this.prevButton.disabled = this.currentPage === 1;
            this.nextButton.disabled = this.currentPage === totalPages || totalPages === 0;
            
            if (this.currentPage === 1) {
                this.prevButton.removeAttribute('aria-current');
            }
        }

        const startIndex = (this.currentPage - 1) * this.itemsPerPage;
        const endIndex = startIndex + this.itemsPerPage;

        this.items.forEach(item => {
            item.classList.add('is-hidden');
            item.style.display = ''; // Clear inline styles
        });
        this.filteredItems.slice(startIndex, endIndex).forEach(item => {
            item.classList.remove('is-hidden');
        });
    }
}

function showGlobalLoading(message) {
    const overlay = document.getElementById('global-loading-overlay');
    const textElement = document.getElementById('global-loading-text');
    if (message && textElement) {
        textElement.innerText = message;
    }
    if (overlay) {
        overlay.classList.remove('hidden');
        overlay.classList.add('flex');
    }
}

document.addEventListener('DOMContentLoaded', () => {
    // Initialize icons if lucide is available
    if (typeof lucide !== 'undefined') {
        lucide.createIcons();
    }

    // Close modals on Escape key press
    document.addEventListener('keydown', function(event) {
        if (event.key === 'Escape') {
            const openModals = document.querySelectorAll('.fixed.inset-0.z-50:not(.hidden)');
            openModals.forEach(modal => {
                // Ensure we don't accidentally close the loading overlay which should block input
                if (modal.id !== 'global-loading-overlay') {
                    modal.classList.add('hidden');
                }
            });
        }
    });

    // User Dropdown toggle and click outside handler
    const userMenuButton = document.getElementById('user-menu-button');
    const userDropdown = document.getElementById('user-dropdown');
    if (userMenuButton && userDropdown) {
        userMenuButton.addEventListener('click', (e) => {
            e.stopPropagation();
            const isHidden = userDropdown.classList.toggle('hidden');
            userMenuButton.setAttribute('aria-expanded', !isHidden);
        });
        document.addEventListener('click', (e) => {
            if (!userMenuButton.contains(e.target) && !userDropdown.contains(e.target)) {
                userDropdown.classList.add('hidden');
                userMenuButton.setAttribute('aria-expanded', 'false');
            }
        });
    }
});
