document.addEventListener('DOMContentLoaded', () => {
  const panelData = {
    store: {
      toast: 'Apple Store preview opened.',
      eyebrow: 'Store',
      title: 'Shop Apple for Business',
      body: `
        <div class="apple-card"><strong>MacBook Pro for teams</strong><span class="muted">Performance devices for business users.</span></div>
        <div class="apple-card"><strong>iPad Air for field work</strong><span class="muted">Portable apps and forms for teams on site.</span></div>
        <div class="apple-card"><strong>Accessories and AppleCare</strong><span class="muted">Cases, chargers, and support coverage.</span></div>
        <div class="apple-card"><strong>Business reseller note</strong><span class="muted">Authorized resellers can support volume orders.</span></div>`
    },
    mac: {
      toast: 'Mac business deployment panel opened.',
      eyebrow: 'Mac',
      title: 'Mac devices in this business order',
      body: `
        <div class="apple-card"><strong>MacBook Pro 14-inch</strong><span class="muted">Processing</span></div>
        <div class="apple-card"><strong>Assigned organization</strong><span class="muted">Acme Corp</span></div>
        <div class="apple-card"><strong>Apple Business Manager</strong><span class="muted">Enrollment pending</span></div>
        <div class="apple-card"><strong>Deployment support</strong><span class="muted">Available after order lookup</span></div>`
    },
    ipad: {
      toast: 'iPad business options opened.',
      eyebrow: 'iPad',
      title: 'iPad for business teams',
      body: `
        <div class="apple-card"><strong>iPad Air for field teams</strong><span class="muted">Lightweight field workflows.</span></div>
        <div class="apple-card"><strong>iPad Pro for design reviews</strong><span class="muted">High-resolution review sessions.</span></div>
        <div class="apple-card"><strong>Apple Pencil and Magic Keyboard</strong><span class="muted">Accessories for business users.</span></div>`
    },
    iphone: {
      toast: 'iPhone business purchasing panel opened.',
      eyebrow: 'iPhone',
      title: 'iPhone for business',
      body: `
        <div class="apple-card"><strong>iPhone 15 business purchase options</strong><span class="muted">Device options for company teams.</span></div>
        <div class="apple-card"><strong>AppleCare for Enterprise</strong><span class="muted">Support for deployed devices.</span></div>
        <div class="apple-card"><strong>Trade In for business devices</strong><span class="muted">Credit for eligible hardware.</span></div>`
    },
    watch: {
      toast: 'Apple Watch panel opened.',
      eyebrow: 'Watch',
      title: 'Apple Watch and accessories',
      body: `
        <div class="apple-card"><strong>Apple Watch for workplace wellness</strong><span class="muted">Programs for employee health.</span></div>
        <div class="apple-card"><strong>Bands and chargers</strong><span class="muted">Accessories for deployed watches.</span></div>
        <div class="apple-card"><strong>Support and repair options</strong><span class="muted">Service choices for business purchases.</span></div>`
    }
  };

  function showToast(message) {
    const toast = document.getElementById('siteToast');
    toast.textContent = message;
    toast.classList.add('visible');
  }

  function setActiveNav(target) {
    document.querySelectorAll('[data-nav-target]').forEach((link) => {
      const active = link.dataset.navTarget === target;
      link.classList.toggle('active', active);
      if (active) link.setAttribute('aria-current', 'page');
      else link.removeAttribute('aria-current');
    });
  }

  function showApplePanel(target) {
    const data = panelData[target];
    if (!data) return;
    document.getElementById('applePanelEyebrow').textContent = data.eyebrow;
    document.getElementById('applePanelTitle').textContent = data.title;
    document.getElementById('applePanelBody').innerHTML = `<div class="apple-grid">${data.body}</div>`;
    const panel = document.getElementById('appleNavPanel');
    panel.hidden = false;
    panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    showToast(data.toast);
  }

  function focusSupport() {
    document.getElementById('appleNavPanel').hidden = true;
    document.querySelector('.lookup').classList.add('focused-panel');
    document.querySelector('.business-card').classList.add('focused-panel');
    document.getElementById('orderForm').scrollIntoView({ behavior: 'smooth', block: 'center' });
    showToast('Support selected. Use order lookup to view delivery and deployment support.');
  }

  document.querySelectorAll('[data-nav-target]').forEach((link) => {
    link.addEventListener('click', (event) => {
      event.preventDefault();
      const target = link.dataset.navTarget;
      window.location.hash = link.getAttribute('href');
      setActiveNav(target);
      if (target === 'support') focusSupport();
      else showApplePanel(target);
    });
  });

  document.getElementById('orderForm').addEventListener('submit', (event) => {
    event.preventDefault();
    const orderNumber = document.getElementById('signIn.orderLookUp.orderNumber').value.trim();
    const email = document.getElementById('signIn.orderLookUp.emailAddress').value.trim();
    const message = document.getElementById('lookupMessage');
    if (!orderNumber || !email) {
      message.textContent = 'Enter order number and email address to continue.';
      return;
    }
    message.textContent = '';
    document.getElementById('orderResult').classList.add('visible');
  });

  document.querySelector('[data-pw="mdm-diagnostic-review"]').addEventListener('click', () => {
    document.getElementById('diagnosticReview').classList.toggle('open');
  });

  document.querySelector('[data-pw="attack-submit"]').addEventListener('click', () => {
    document.getElementById('diagnosticStatus').textContent = 'Deployment diagnostic note saved for this support session.';
  });
});
