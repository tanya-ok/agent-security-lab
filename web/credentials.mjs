// SPDX-License-Identifier: Apache-2.0
// Expiration is separate from service readiness and successful sign-in.
export function credentialView(value, now = Date.now()) {
  const state = ['current', 'expiring', 'expired', 'stopped'].includes(value?.state) ? value.state : 'unknown';
  const titles = {
    current: 'Test credentials have an expiry date',
    expiring: 'Test credentials expire soon',
    expired: 'Test credentials have expired',
    stopped: 'Test credential checks are paused',
    unknown: 'Test credential expiry is unknown',
  };
  const messages = {
    current: 'Warnings appear 24 hours before expiry. A ready service does not prove that sign-in works.',
    expiring: 'Plan to recreate the disposable test identity profile before access expires.',
    expired: 'Sign-in or profile checks may fail even while services look healthy. Reconnecting local access does not renew credentials.',
    stopped: 'Start the security stack to read the current identity metadata.',
    unknown: 'The current expiry could not be verified. No remaining lifetime or successful access is assumed.',
  };
  const items = [];
  for (const [id, name] of [['bootstrap', 'Profile bootstrap'], ['login', 'ZITADEL Login']]) {
    const item = Array.isArray(value?.items) ? value.items.find((row) => row?.id === id) : undefined;
    const expires = typeof item?.expires_at === 'string' ? Date.parse(item.expires_at) : NaN;
    let text = 'Expiry unavailable';
    if (item?.state !== 'unknown' && Number.isFinite(expires)) {
      const minutes = expires <= now ? Math.floor((now - expires) / 60000) : Math.ceil((expires - now) / 60000);
      const duration = minutes < 60 ? `${minutes}m` : `${Math.floor(minutes / 60)}h ${minutes % 60}m`;
      text = expires <= now ? (minutes ? `Expired ${duration} ago` : 'Expired just now') : `Expires in ${duration}`;
    }
    items.push({id, name, text, expires_at: item?.state !== 'unknown' && Number.isFinite(expires) ? item.expires_at : null});
  }
  return {
    state, title: titles[state], message: messages[state], items,
    guidance: ['expiring', 'expired'].includes(state)
      ? 'Overview: Stop stack, then Start stack recreates test identities, keys and notes. GRC data and saved reports remain. No automatic reset is performed.'
      : null,
  };
}
