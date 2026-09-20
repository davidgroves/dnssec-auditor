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
