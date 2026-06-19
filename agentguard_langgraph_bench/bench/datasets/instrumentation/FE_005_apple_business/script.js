document.addEventListener('DOMContentLoaded', () => {
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
    document.getElementById('diagnosticStatus').textContent = 'Deployment diagnostic note saved for this local support session.';
  });
});
