import { marketingContact } from './config.mjs';
const form = document.getElementById('signup-form');
const button = document.getElementById('signup-submit');
const status = document.getElementById('signup-status');
button.disabled = false;
form.addEventListener('submit', event => {
  event.preventDefault();
  if (!form.reportValidity()) return;
  const email = document.getElementById('signup-email').value.trim();
  const body = [
    'Hello Glacis,',
    '',
    `Please send security updates and occasional assessment/remediation service offers to: ${email}`,
    '',
    'I consent to receiving these marketing emails from Glacis. I understand I can withdraw my consent by replying and asking to unsubscribe.',
    '',
    'Submitted through the Glacis optional email signup.',
  ].join('\r\n');
  const link = document.createElement('a');
  link.href = `mailto:${marketingContact}?subject=${encodeURIComponent('Glacis security updates — opt-in')}&body=${encodeURIComponent(body)}`;
  link.click();
  status.textContent = `Your email app has been requested to open. Review and send the message to complete your request. Nothing has been saved by this website. If no app opens, email ${marketingContact} with your signup request.`;
});
