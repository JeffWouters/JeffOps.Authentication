// No identity SDK and no tokens in the browser: the BFF holds them and sets an HttpOnly session cookie.
// Every state-changing request sends the CSRF header; the cookie is sent automatically (same origin).
const csrf = { 'X-JeffOps-Csrf': '1' };
const $ = id => document.getElementById(id);

async function refresh() {
  const response = await fetch('/bff/me', { credentials: 'include' });
  const signedIn = response.ok;
  $('status').textContent = signedIn ? `Signed in as ${(await response.json()).email}` : 'Not signed in';
  $('login').hidden = signedIn;
  $('logout').hidden = !signedIn;
  $('call').hidden = !signedIn;
}

$('login').onclick = () => { location.href = `/bff/login?returnUrl=${encodeURIComponent(location.pathname)}`; };

$('logout').onclick = async () => {
  const response = await fetch('/bff/logout', { method: 'POST', credentials: 'include', headers: csrf });
  const { endSessionUrl } = await response.json();
  location.href = endSessionUrl; // also end the session at the token server
};

$('call').onclick = async () => {
  const response = await fetch('/api/whoami', { credentials: 'include' });
  $('output').textContent = `${response.status}\n${await response.text()}`;
};

refresh();
