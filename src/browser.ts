import { CompactEncrypt, importJWK } from 'jose';

const form = document.querySelector<HTMLFormElement>('#login-form')!;
const status = document.querySelector<HTMLElement>('#status')!;
const config = JSON.parse(document.querySelector('#relay-config')!.textContent!);
const encoder = new TextEncoder();
let submitting = false;
form.addEventListener('submit', async event => {
  event.preventDefault();
  if (submitting) return;
  submitting = true;
  const button = form.querySelector<HTMLButtonElement>('button')!;
  const username = form.elements.namedItem('username') as HTMLInputElement;
  const password = form.elements.namedItem('password') as HTMLInputElement;
  button.disabled = true;
  let bytes: Uint8Array | undefined;
  try {
    if (!username.value || !password.value || encoder.encode(username.value).length > 512
        || encoder.encode(password.value).length > 4096) throw new Error();
    const deliveryId = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    bytes = encoder.encode(JSON.stringify({ requestId: config.id, slug: config.slug,
      targetOrigin: config.targetOrigin, deliveryId, username: username.value, password: password.value }));
    const key = await importJWK(config.recipientPublicKey, 'RSA-OAEP-256');
    const jwe = await new CompactEncrypt(bytes).setProtectedHeader({ alg: 'RSA-OAEP-256', enc: 'A256GCM',
      typ: 'JWE', kid: config.id }).encrypt(key);
    // Clear controls before transmitting the ciphertext. No form POST ever
    // contains raw credentials, and no password is included in error text.
    username.value = ''; password.value = ''; bytes.fill(0); bytes = undefined;
    const response = await fetch(`/login?id=${encodeURIComponent(config.id)}`, { method: 'POST',
      credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ csrf: config.csrf, deliveryId, jwe }) });
    if (!response.ok) throw new Error();
    form.reset(); form.querySelectorAll<HTMLInputElement>('input').forEach(input => input.disabled = true);
    status.textContent = 'Encrypted credentials sent to your waiting client. You can close this page.';
  } catch {
    username.value = ''; password.value = ''; button.disabled = true;
    status.textContent = 'This request could not be completed. Ask the waiting client for a new link.';
  } finally { bytes?.fill(0); }
});
