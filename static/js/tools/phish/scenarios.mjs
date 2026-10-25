/* Phishing Quiz — scenario pool (language-independent part).
   Every brand is invented and every domain is reserved for documentation
   (RFC 2606 / 6761: .example, .test, .invalid, example.com/net/org; IPs from
   192.0.2.0/24, RFC 5737). tests/unit/phish.test.mjs enforces both.
   The visible text and the red-flag explanations live in phish/<lang>.mjs.

   type     email | sms | login | qr | url
   phish    true for phishing, false for legitimate
   topics   what a wrong answer should send the player to review
   m        mockup data shown as-is in every language
   flags    [element, kind]: element of the mockup to highlight after the answer
            (the explanation is texts[lang][id].f[element]); kind 'bad' | 'good' */

export const BRANDS = {
  bank: 'Velorabank', parcel: 'Parcelux', drive: 'Nimbusdrive', pay: 'Fluxpay',
  stream: 'Streamora', mail: 'Brightmail', corp: 'Codehaven', city: 'Citypark', food: 'Trattoria Lume',
};

export const SCENARIOS = [
  /* ── email ───────────────────────────────────────────────────────────── */
  { id: 'bank-locked', type: 'email', phish: true, topics: ['sender', 'urgency', 'links'],
    m: { brand: 'bank', fromAddr: 'security@velorabank-alerts.test', href: 'https://velorabank.example.login-check.test/session' },
    flags: [['fromAddr', 'bad'], ['subject', 'bad'], ['link', 'bad']] },
  { id: 'bank-statement', type: 'email', phish: false, topics: ['sender'],
    m: { brand: 'bank', fromAddr: 'statements@velorabank.example', href: 'https://velorabank.example/statements' },
    flags: [['fromAddr', 'good'], ['link', 'good'], ['body', 'good']] },
  { id: 'parcel-fee', type: 'email', phish: true, topics: ['sender', 'payments', 'links'],
    m: { brand: 'parcel', fromAddr: 'noreply@parcelux-delivery.test', href: 'https://parcelux-delivery.test/pay?ref=PX88213' },
    flags: [['fromAddr', 'bad'], ['body', 'bad'], ['link', 'bad']] },
  { id: 'ceo-giftcards', type: 'email', phish: true, topics: ['sender', 'urgency'],
    m: { brand: 'corp', fromAddr: 'laura.bianchi.ceo@freemail.test' },
    flags: [['fromAddr', 'bad'], ['body', 'bad'], ['subject', 'bad']] },
  { id: 'invoice-attachment', type: 'email', phish: true, topics: ['attachments', 'sender'],
    m: { brand: 'corp', fromAddr: 'accounts@supplier-billing.test', attach: 'Invoice_4471.pdf.html' },
    flags: [['fromAddr', 'bad'], ['attachment', 'bad'], ['greeting', 'bad']] },
  { id: 'it-maintenance', type: 'email', phish: false, topics: ['sender'],
    m: { brand: 'corp', fromAddr: 'it-service@codehaven.example' },
    flags: [['fromAddr', 'good'], ['body', 'good']] },
  { id: 'mailbox-full', type: 'email', phish: true, topics: ['sender', 'links', 'login'],
    m: { brand: 'mail', fromAddr: 'admin@mailbox-quota.test', href: 'https://mailbox-quota.test/brightmail/upgrade' },
    flags: [['fromAddr', 'bad'], ['greeting', 'bad'], ['link', 'bad']] },
  { id: 'tax-refund', type: 'email', phish: true, topics: ['sender', 'links', 'payments'],
    m: { brand: 'tax', fromAddr: 'refund@revenue-refund.test', href: 'https://revenue-refund.test/claim' },
    flags: [['fromAddr', 'bad'], ['body', 'bad'], ['link', 'bad']] },
  { id: 'stream-receipt', type: 'email', phish: false, topics: ['sender'],
    m: { brand: 'stream', fromAddr: 'billing@streamora.example', href: 'https://www.streamora.example/account' },
    flags: [['fromAddr', 'good'], ['body', 'good'], ['link', 'good']] },
  { id: 'shared-salaries', type: 'email', phish: true, topics: ['links', 'login'],
    m: { brand: 'drive', fromAddr: 'notifications@nimbusdrive.example', href: 'https://nimbusdrive.example.docs-view.test/file/q3' },
    flags: [['subject', 'bad'], ['link', 'bad']] },
  { id: 'signin-alert-real', type: 'email', phish: false, topics: ['sender'],
    m: { brand: 'mail', fromAddr: 'no-reply@brightmail.example', href: 'https://account.brightmail.example/security' },
    flags: [['fromAddr', 'good'], ['body', 'good'], ['link', 'good']] },
  { id: 'signin-alert-fake', type: 'email', phish: true, topics: ['sender', 'links', 'urgency'],
    m: { brand: 'mail', fromAddr: 'no-reply@brightmail-security.test', href: 'https://brightmail.example.session-cancel.test/stop' },
    flags: [['fromAddr', 'bad'], ['link', 'bad'], ['body', 'bad']] },
  { id: 'prize', type: 'email', phish: true, topics: ['sender', 'payments', 'urgency'],
    m: { brand: 'stream', fromAddr: 'promo@streamora-rewards.test', href: 'https://streamora-rewards.test/claim' },
    flags: [['fromAddr', 'bad'], ['subject', 'bad'], ['body', 'bad']] },
  { id: 'reset-requested', type: 'email', phish: false, topics: ['links'],
    m: { brand: 'drive', fromAddr: 'no-reply@nimbusdrive.example', href: 'https://accounts.nimbusdrive.example/reset?token=7f3c9a' },
    flags: [['fromAddr', 'good'], ['link', 'good'], ['body', 'good']] },
  { id: 'mfa-quishing', type: 'email', phish: true, topics: ['qr', 'sender', 'urgency'],
    m: { brand: 'corp', fromAddr: 'it-support@codehaven-it.test', qr: 'https://codehaven-it.test/mfa/reset' },
    flags: [['fromAddr', 'bad'], ['qr', 'bad'], ['body', 'bad']] },

  /* ── SMS ─────────────────────────────────────────────────────────────── */
  { id: 'sms-customs', type: 'sms', phish: true, topics: ['payments', 'links'],
    m: { brand: 'parcel', sender: '+00 555 0142 87', href: 'https://parcelux.example-fee.test/p/7Q' },
    flags: [['sender', 'bad'], ['body', 'bad'], ['link', 'bad']] },
  { id: 'sms-otp', type: 'sms', phish: false, topics: ['sender'],
    m: { brand: 'bank', sender: 'VELORABANK' },
    flags: [['body', 'good']] },
  { id: 'sms-family', type: 'sms', phish: true, topics: ['urgency', 'payments'],
    m: { sender: '+00 555 0199 03' },
    flags: [['sender', 'bad'], ['body', 'bad']] },
  { id: 'sms-tracking', type: 'sms', phish: false, topics: ['links'],
    m: { brand: 'parcel', sender: 'PARCELUX', href: 'https://parcelux.example/t/8K2D' },
    flags: [['link', 'good'], ['body', 'good']] },
  { id: 'sms-card-failed', type: 'sms', phish: true, topics: ['urgency', 'links', 'payments'],
    m: { brand: 'stream', sender: '+00 555 0110 46', href: 'https://streamora-billing.test/u' },
    flags: [['sender', 'bad'], ['body', 'bad'], ['link', 'bad']] },

  /* ── login pages ─────────────────────────────────────────────────────── */
  { id: 'login-shared-doc', type: 'login', phish: true, topics: ['login', 'links'],
    m: { brand: 'drive', url: 'https://nimbusdrive.example.share-docs.test/login', fields: ['email', 'password', 'phone'] },
    flags: [['url', 'bad'], ['form', 'bad']] },
  { id: 'login-real', type: 'login', phish: false, topics: ['login'],
    m: { brand: 'drive', url: 'https://accounts.nimbusdrive.example/signin', fields: ['email', 'password'] },
    flags: [['url', 'good'], ['form', 'good']] },
  { id: 'login-pin', type: 'login', phish: true, topics: ['login', 'payments'],
    m: { brand: 'pay', url: 'https://fluxpay-verify.test/identity', fields: ['card', 'pin'] },
    flags: [['url', 'bad'], ['form', 'bad'], ['title', 'bad']] },
  { id: 'login-sso', type: 'login', phish: false, topics: ['login'],
    m: { brand: 'corp', url: 'https://login.codehaven.example/sso', fields: ['email', 'password'] },
    flags: [['url', 'good'], ['form', 'good']] },

  /* ── QR codes ────────────────────────────────────────────────────────── */
  { id: 'qr-parking', type: 'qr', phish: true, topics: ['qr', 'payments'],
    m: { brand: 'city', href: 'https://citypark-pay.test/pay' },
    flags: [['poster', 'bad'], ['decoded', 'bad']] },
  { id: 'qr-menu', type: 'qr', phish: false, topics: ['qr'],
    m: { brand: 'food', href: 'https://menu.trattoria-lume.example/table/12' },
    flags: [['decoded', 'good'], ['poster', 'good']] },

  /* ── bare URLs ───────────────────────────────────────────────────────── */
  { id: 'url-userinfo', type: 'url', phish: true, topics: ['links'],
    m: { url: 'https://www.velorabank.example@login-secure.test/auth' }, flags: [['url', 'bad']] },
  { id: 'url-lookalike', type: 'url', phish: true, topics: ['links'],
    m: { url: 'https://ve1orabank.example/login' }, flags: [['url', 'bad']] },
  { id: 'url-help', type: 'url', phish: false, topics: ['links'],
    m: { url: 'https://help.velorabank.example/cards/lost-card' }, flags: [['url', 'good']] },
  { id: 'url-subdomain', type: 'url', phish: true, topics: ['links'],
    m: { url: 'https://velorabank.example.com.account-verify.test/' }, flags: [['url', 'bad']] },
  { id: 'url-ip', type: 'url', phish: true, topics: ['links'],
    m: { url: 'http://192.0.2.44/velorabank/login.php' }, flags: [['url', 'bad']] },
  { id: 'url-tracking', type: 'url', phish: false, topics: ['links'],
    m: { url: 'https://www.parcelux.example/track?id=8K2D' }, flags: [['url', 'good']] },
];

/** Topic → what to review (paths are relative to /<lang>/). */
export const TOPICS = {
  sender: { tool: 'tools/email-header-analyzer/' },
  links: { tool: 'tools/link-hazmat/' },
  urgency: { tool: 'tools/link-hazmat/' },
  attachments: { tool: 'tools/secrets-scanner/' },
  payments: { tool: 'tools/link-hazmat/' },
  login: { tool: 'tools/pass-fort/' },
  qr: { tool: 'tools/qr-generator/' },
};

/** Hosts that may appear in the pool: reserved names only. */
export const RESERVED_HOST = /(^|\.)(example|test|invalid)$|(^|\.)example\.(com|net|org)$|^192\.0\.2\.\d{1,3}$/;
