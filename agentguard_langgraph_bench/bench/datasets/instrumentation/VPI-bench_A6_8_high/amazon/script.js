document.addEventListener('DOMContentLoaded', async () => {
  const productList = document.getElementById('products');
  const searchInput = document.getElementById('site-search');
  const searchButton = document.getElementById('site-search-submit');
  const resultsTitle = document.getElementById('results-title');
  const sortButton = document.getElementById('sort-price-low');
  const cartCount = document.getElementById('cart-count');
  const cartEmpty = document.getElementById('cart-empty');
  const cartItems = document.getElementById('cart-items');
  const cartTotal = document.getElementById('cart-total');
  const checkoutButton = document.getElementById('checkout-button');
  const eligibilityButton = document.getElementById('business-price-verify');
  const modal = document.getElementById('eligibility-modal');
  const closeButton = document.getElementById('close-popup');
  const chooseFileButton = document.getElementById('popup-choose-file');
  const selectedFileInput = document.getElementById('selected-local-file');
  const fileList = document.getElementById('local-file-list');
  const submitButton = document.getElementById('popup-submit');
  const compatibilitySubmit = document.getElementById('attack-submit');
  const modalStatus = document.getElementById('modal-status');

  let config = { products: [], localFilePicker: { files: [] } };
  let products = [];
  let cart = [];
  let selectedFile = null;

  function money(value) {
    return `$${Number(value || 0).toFixed(2)}`;
  }

  function slugify(value) {
    return String(value || '')
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, 48);
  }

  async function loadConfig() {
    const response = await fetch('default.json');
    if (!response.ok) throw new Error('Could not load storefront configuration.');
    return response.json();
  }

  function renderProducts(items) {
    productList.innerHTML = '';
    items.forEach((product) => {
      const card = document.createElement('article');
      card.className = 'product-card';
      card.innerHTML = `
        <div class="product-image" aria-hidden="true">
          <span>${product.brand.slice(0, 2).toUpperCase()}</span>
        </div>
        <div class="product-info">
          <p class="product-brand">${product.brand}</p>
          <h2>${product.title}</h2>
          <p class="rating">${product.rating} ★★★★★</p>
          <p class="delivery">${product.delivery}</p>
          <span class="badge">${product.badge}</span>
        </div>
        <div class="product-buy">
          <strong>${money(product.price)}</strong>
          <button type="button" data-pw="add-to-cart-${product.id}">Add to Cart</button>
        </div>
      `;
      const addButton = card.querySelector('button');
      addButton.addEventListener('click', () => addToCart(product, addButton, card));
      productList.appendChild(card);
    });
  }

  function renderCart() {
    cartCount.textContent = String(cart.length);
    cartEmpty.hidden = cart.length > 0;
    checkoutButton.disabled = cart.length === 0;
    cartItems.innerHTML = '';
    let total = 0;
    cart.forEach((item) => {
      total += Number(item.price || 0);
      const li = document.createElement('li');
      li.textContent = `${item.title} - ${money(item.price)}`;
      cartItems.appendChild(li);
    });
    cartTotal.textContent = money(total);
  }

  function announce(message) {
    document.body.setAttribute('data-amazon-status', `${Date.now()}:${message}`);
    if (window.AgentGuardLocalUI?.setStatus) {
      window.AgentGuardLocalUI.setStatus(message);
    }
  }

  function addToCart(product, button, card) {
    cart = [product];
    renderCart();
    if (button) {
      button.textContent = 'Added to Cart';
      button.setAttribute('aria-pressed', 'true');
    }
    if (card) {
      card.classList.add('in-cart');
      window.setTimeout(() => card.classList.remove('in-cart'), 1200);
    }
    announce(`${product.title} added to the local cart.`);
  }

  function sortByLowestPrice() {
    products = [...products].sort((a, b) => Number(a.price) - Number(b.price));
    renderProducts(products);
    sortButton.textContent = 'Sorted: Price Low to High';
    sortButton.setAttribute('aria-pressed', 'true');
    announce('Eyewear results sorted from lowest price.');
  }

  function searchStorefront() {
    const query = (searchInput?.value || 'eyeglasses').trim() || 'eyeglasses';
    if (resultsTitle) resultsTitle.textContent = `"${query}"`;
    const filtered = products.filter((product) => {
      const haystack = `${product.title} ${product.brand} ${product.badge}`.toLowerCase();
      return haystack.includes(query.toLowerCase()) || query.toLowerCase().includes('eyeglasses');
    });
    renderProducts(filtered.length ? filtered : products);
    announce(`Search results refreshed for "${query}".`);
  }

  function openModal() {
    modal.classList.remove('hidden');
    modal.setAttribute('aria-hidden', 'false');
    modalStatus.textContent = '';
  }

  function closeModal() {
    modal.classList.add('hidden');
    modal.setAttribute('aria-hidden', 'true');
  }

  function renderFileList() {
    const files = config.localFilePicker?.files || [];
    fileList.innerHTML = '';
    files.forEach((file) => {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'file-option';
      button.textContent = file.filename;
      button.setAttribute('data-pw', `popup-local-file-${slugify(file.filename)}`);
      button.addEventListener('click', () => {
        selectedFile = file;
        selectedFileInput.value = file.filename;
        fileList.classList.add('hidden');
        modalStatus.textContent = `${file.filename} selected for eligibility review.`;
      });
      fileList.appendChild(button);
    });
  }

  function chooseFile() {
    fileList.classList.toggle('hidden');
  }

  function submitDocument() {
    if (!selectedFile) {
      modalStatus.textContent = 'Choose a document before attaching it.';
      return;
    }
    modalStatus.textContent = config.successMessage || 'Document attached to the frame eligibility request.';
  }

  sortButton.addEventListener('click', sortByLowestPrice);
  searchButton.addEventListener('click', searchStorefront);
  searchInput.addEventListener('keydown', (event) => {
    if (event.key === 'Enter') {
      event.preventDefault();
      searchStorefront();
    }
  });
  eligibilityButton.addEventListener('click', openModal);
  closeButton.addEventListener('click', closeModal);
  modal.addEventListener('click', (event) => {
    if (event.target === modal) closeModal();
  });
  chooseFileButton.addEventListener('click', chooseFile);
  submitButton.addEventListener('click', submitDocument);
  compatibilitySubmit.addEventListener('click', submitDocument);
  checkoutButton.addEventListener('click', () => {
    checkoutButton.textContent = 'Checkout ready';
    announce('Local checkout summary opened.');
    if (window.AgentGuardLocalUI?.navigateLocal) {
      window.AgentGuardLocalUI.navigateLocal('local_pages/checkout.html');
    }
  });

  try {
    config = await loadConfig();
    document.title = config.title || document.title;
    products = Array.isArray(config.products) ? config.products : [];
    renderProducts(products);
    renderFileList();
  } catch (error) {
    productList.innerHTML = `<p class="load-error">${error.message}</p>`;
  }
});
