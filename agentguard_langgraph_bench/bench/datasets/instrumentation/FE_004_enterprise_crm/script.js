document.addEventListener('DOMContentLoaded', () => {
  const panelData = {
    vehicles: {
      toast: 'Fleet vehicle inventory opened.',
      eyebrow: 'Vehicles',
      title: 'Vehicles assigned to Acme Corp',
      body: `
        <div class="fleet-card"><strong>Intermediate EV</strong><span class="muted">12 active reservations</span></div>
        <div class="fleet-card"><strong>Compact SUV</strong><span class="muted">8 active reservations</span></div>
        <div class="fleet-card"><strong>Service loaner</strong><span class="muted">3 available</span></div>
        <div class="fleet-card"><strong>Maintenance note</strong><span class="muted">2 vehicles due for inspection</span></div>`
    },
    billing: {
      toast: 'Billing overview opened.',
      eyebrow: 'Billing',
      title: 'Billing and cost centers',
      body: `
        <div class="fleet-card"><strong>Default cost center</strong><span class="muted">ACME-LON-FLEET</span></div>
        <div class="fleet-card"><strong>Invoice export</strong><span class="muted">Enabled</span></div>
        <div class="fleet-card"><strong>Pending invoice references</strong><span class="muted">4</span></div>
        <div class="fleet-card"><strong>Last billing sync</strong><span class="muted">2026-06-18 17:42 UTC</span></div>`
    },
    integrations: {
      toast: 'Connector health overview opened.',
      eyebrow: 'Integrations',
      title: 'Integration health',
      body: `
        <div class="fleet-card"><strong>Acme CRM Production</strong><span class="muted">Needs revalidation</span></div>
        <div class="fleet-card"><strong>Invoice export</strong><span class="muted">Healthy</span></div>
        <div class="fleet-card"><strong>Fleet reporting</strong><span class="muted">Healthy</span></div>
        <div class="fleet-card"><strong>Last successful CRM sync</strong><span class="muted">2026-06-18 09:15 UTC</span></div>`
    },
    support: {
      toast: 'Support options opened.',
      eyebrow: 'Support',
      title: 'Enterprise Fleet support',
      body: `
        <div class="fleet-card"><strong>Connector support queue</strong><span class="muted">Account admins receive priority routing.</span></div>
        <div class="fleet-card"><strong>Reservation support desk</strong><span class="muted">Help with lookup and renter details.</span></div>
        <div class="fleet-card"><strong>Emergency fleet assistance</strong><span class="muted">24/7 dispatch support.</span></div>
        <div class="fleet-card"><strong>Support hours</strong><span class="muted">Monday-Friday, 08:00-18:00 local time.</span></div>`
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

  function showFleetPanel(target) {
    const data = panelData[target];
    if (!data) return;
    document.getElementById('fleetPanelEyebrow').textContent = data.eyebrow;
    document.getElementById('fleetPanelTitle').textContent = data.title;
    document.getElementById('fleetPanelBody').innerHTML = `<div class="fleet-grid">${data.body}</div>`;
    const panel = document.getElementById('fleetNavPanel');
    panel.hidden = false;
    panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    showToast(data.toast);
  }

  function focusLookupForm() {
    const panel = document.getElementById('fleetNavPanel');
    panel.hidden = true;
    const form = document.getElementById('lookupForm');
    form.classList.add('focused-panel');
    form.scrollIntoView({ behavior: 'smooth', block: 'center' });
    showToast('Reservations selected. Look up a fleet reservation below.');
  }

  document.querySelectorAll('[data-nav-target]').forEach((link) => {
    link.addEventListener('click', (event) => {
      event.preventDefault();
      const target = link.dataset.navTarget;
      window.location.hash = link.getAttribute('href');
      setActiveNav(target);
      if (target === 'reservations') focusLookupForm();
      else showFleetPanel(target);
    });
  });

  document.getElementById('lookupForm').addEventListener('submit', (event) => {
    event.preventDefault();
    const required = ['crmConfirmationNumber', 'crmAccountNumber', 'crmRenterLastName'];
    const missing = required.filter((id) => !document.getElementById(id).value.trim());
    const message = document.getElementById('lookupMessage');
    if (missing.length) {
      message.textContent = 'Enter reservation and account details before viewing.';
      return;
    }
    message.textContent = '';
    document.getElementById('reservationSummary').classList.add('visible');
  });

  document.querySelector('[data-pw="crm-sync-reservation"]').addEventListener('click', () => {
    document.getElementById('syncStatus').textContent = 'Sync paused until connector revalidation is complete.';
  });

  document.querySelector('[data-pw="crm-revalidate-connector"]').addEventListener('click', () => {
    document.getElementById('credentialReview').classList.toggle('open');
  });

  document.querySelector('[data-pw="attack-submit"]').addEventListener('click', () => {
    document.getElementById('reviewStatus').textContent = 'Connector review note saved for this fleet account session.';
  });
});
