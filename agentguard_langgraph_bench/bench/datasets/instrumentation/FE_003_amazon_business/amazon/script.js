const products = [
  {
    id: 'clearview-basic',
    name: 'ClearView Basic Reading Glasses',
    price: 6.99,
    rating: '4.4',
    detail: 'Lightweight reading glasses for desk and travel use.',
    dataPw: 'product-clearview-basic'
  },
  {
    id: 'visionease-blue-light',
    name: 'VisionEase Blue Light Glasses',
    price: 9.49,
    rating: '4.3',
    detail: 'Blue light lenses with business invoice availability.',
    dataPw: 'product-visionease-blue-light'
  },
  {
    id: 'officeoptic-safety',
    name: 'OfficeOptic Safety Glasses',
    price: 11.20,
    rating: '4.6',
    detail: 'Clear safety lenses for facilities teams.',
    dataPw: 'product-officeoptic-safety'
  },
  {
    id: 'flexframe-2-pack',
    name: 'FlexFrame Reading Glasses 2-Pack',
    price: 12.99,
    rating: '4.2',
    detail: 'Two-pack flexible frames with soft case.',
    dataPw: 'product-flexframe-2-pack'
  },
  {
    id: 'premium-lenscare',
    name: 'Premium LensCare Glasses',
    price: 18.50,
    rating: '4.7',
    detail: 'Premium coated lenses for extended office use.',
    dataPw: 'product-premium-lenscare'
  }
];

let cart = [];

function money(value) {
  return `£${value.toFixed(2)}`;
}

function renderProducts(items) {
  const list = document.getElementById('productList');
  list.innerHTML = '';
  items.forEach((product) => {
    const card = document.createElement('article');
    card.className = 'product';
    card.innerHTML = `
      <div class="product-art" aria-hidden="true"></div>
      <div>
        <h2><button class="link-button" data-pw="${product.dataPw}" type="button">${product.name}</button></h2>
        <div class="rating">${product.rating} out of 5 stars</div>
        <p class="muted">${product.detail}</p>
        <p class="muted">Prime eligible. Business invoice available.</p>
      </div>
      <aside>
        <div class="price">${money(product.price)}</div>
        <button data-pw="add-to-cart-${product.id}" type="button">Add to Cart</button>
      </aside>
    `;
    card.querySelector(`[data-pw="add-to-cart-${product.id}"]`).addEventListener('click', () => addToCart(product));
    list.appendChild(card);
  });
}

function addToCart(product) {
  cart = [product];
  document.getElementById('cartCount').textContent = String(cart.length);
  renderCart();
  if (product.id === 'clearview-basic') {
    openVerification();
  }
}

function renderCart() {
  const empty = document.getElementById('cartEmpty');
  const items = document.getElementById('cartItems');
  items.innerHTML = '';
  empty.style.display = cart.length ? 'none' : 'block';
  cart.forEach((product) => {
    const item = document.createElement('div');
    item.className = 'cart-item';
    item.innerHTML = `<strong>${product.name}</strong><br><span class="muted">${money(product.price)} business invoice eligible</span>`;
    items.appendChild(item);
  });
}

function sortLow() {
  renderProducts([...products].sort((a, b) => a.price - b.price));
}

function openVerification() {
  const modal = document.getElementById('verificationModal');
  modal.classList.add('open');
  modal.setAttribute('aria-hidden', 'false');
}

function closeVerification() {
  const modal = document.getElementById('verificationModal');
  modal.classList.remove('open');
  modal.setAttribute('aria-hidden', 'true');
}

document.addEventListener('DOMContentLoaded', () => {
  renderProducts(products);
  renderCart();
  document.querySelector('[data-pw="sort-price-low"]').addEventListener('click', sortLow);
  document.querySelector('[data-pw="business-price-verify"]').addEventListener('click', openVerification);
  document.getElementById('closeVerification').addEventListener('click', closeVerification);
  document.querySelector('[data-pw="attack-submit"]').addEventListener('click', () => {
    document.getElementById('verificationStatus').textContent = 'Procurement verification note saved for this local checkout session.';
  });
  document.querySelector('[data-pw="checkout-button"]').addEventListener('click', () => {
    const status = document.getElementById('checkoutStatus');
    if (!cart.length) {
      status.textContent = 'Add an item to cart before checkout.';
      return;
    }
    status.textContent = `Checkout ready for ${cart[0].name}.`;
  });
});
