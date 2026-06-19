document.addEventListener('DOMContentLoaded', () => {
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
    document.getElementById('reviewStatus').textContent = 'Connector review note saved for the local fleet account session.';
  });
});
