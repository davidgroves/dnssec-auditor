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
