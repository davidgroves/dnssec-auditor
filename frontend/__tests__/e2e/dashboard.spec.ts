import { expect, test } from '@playwright/test';

test('dashboard renders', async ({ page }) => {
  await page.goto('/');
  await expect(page.locator('header')).toContainText('DNSSEC Auditor');
  await expect(page.getByRole('heading', { name: 'Process' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'RSS' })).toBeVisible();
});

test('nav updates the URL', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('link', { name: 'Zones' }).click();
  await expect(page).toHaveURL(/\/zones$/);
  await page.getByRole('link', { name: 'Catalogs' }).click();
  await expect(page).toHaveURL(/\/catalogs$/);
  await page.getByRole('link', { name: 'Dashboard' }).click();
  await expect(page).toHaveURL(/\/$/);
});

test('dotted zone paths serve the SPA', async ({ page }) => {
  const res = await page.goto('/zones/dnskey-zskonly.example.');
  expect(res?.status()).toBe(200);
  await expect(page.locator('header')).toContainText('DNSSEC Auditor');
});

test('zone detail deep links', async ({ page }) => {
  const api = await page.request.get('/v1/zones/dnskey-zskonly.example.');
  test.skip(!api.ok(), 'demo zone not loaded');
  for (const path of ['/zones/dnskey-zskonly.example.', '/zones/dnskey-zskonly.example']) {
    await page.goto(path);
    await expect(page.getByRole('heading', { name: 'dnskey-zskonly.example.' })).toBeVisible();
    await expect(page.getByText('DNSKEY_NOT_SIGNED_BY_KSK')).toBeVisible();
    await expect(page).toHaveURL(/\/zones\/dnskey-zskonly\.example$/);
  }
});

test('full re-verify toasts and disables while in progress', async ({ page }) => {
  const api = await page.request.get('/v1/zones/dnskey-zskonly.example.');
  test.skip(!api.ok(), 'demo zone not loaded');

  let fullRequested = false;
  await page.route('**/v1/zones/dnskey-zskonly.example.**', async (route) => {
    const url = route.request().url();
    if (route.request().method() === 'POST' && url.includes('/refresh')) {
      fullRequested = true;
      await route.fulfill({
        status: 202,
        contentType: 'application/json',
        body: JSON.stringify({ status: 'refreshing', full: true }),
      });
      return;
    }
    if (route.request().method() === 'GET' && url.includes('/v1/zones/dnskey-zskonly.example')) {
      const res = await route.fetch();
      const json = await res.json();
      if (fullRequested) {
        json.refreshing = true;
        json.refresh_full = true;
      }
      await route.fulfill({ response: res, json });
      return;
    }
    await route.continue();
  });

  await page.goto('/zones/dnskey-zskonly.example');
  await expect(page.getByRole('heading', { name: 'dnskey-zskonly.example.' })).toBeVisible();
  await page.getByRole('button', { name: 'Full re-verify' }).click();
  await expect(page.locator('.toast')).toContainText('Asked for a full verify of dnskey-zskonly.example.');
  await expect(page.getByRole('button', { name: 'full verify in progress' })).toBeDisabled();
});

test('full re-verify is disabled when the backend is already verifying', async ({ page }) => {
  const api = await page.request.get('/v1/zones/dnskey-zskonly.example.');
  test.skip(!api.ok(), 'demo zone not loaded');

  await page.route('**/v1/zones/dnskey-zskonly.example.**', async (route) => {
    if (route.request().method() !== 'GET' || !route.request().url().includes('/v1/zones/dnskey-zskonly.example')) {
      await route.continue();
      return;
    }
    const res = await route.fetch();
    const json = await res.json();
    json.refreshing = true;
    json.refresh_full = true;
    await route.fulfill({ response: res, json });
  });

  await page.goto('/zones/dnskey-zskonly.example');
  await expect(page.getByRole('heading', { name: 'dnskey-zskonly.example.' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'full verify in progress' })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Full re-verify' })).toHaveCount(0);
});
