const { test, expect } = require('@playwright/test');

test('Lite smoke: start → answer → evaluate → next', async ({ page }) => {
  await page.goto('/app');

  // Make sure the app loaded
  await expect(page.locator('h1')).toContainText('Sanal Mülakatım');

  // Start interview with 2 questions
  await page.fill('#role', 'doktor');
  await page.fill('#nQuestions', '2');
  await page.click('#startBtn');

  await expect(page.locator('#interviewCard')).toBeVisible();
  await expect(page.locator('#questionText')).not.toHaveText('—');

  await page.fill('#answer', 'Test cevap: STAR (Durum, Görev, Eylem, Sonuç) kullanacağım.');
  await page.click('#evalBtn');

  // Feedback should appear (this can take time if OpenAI is used)
  await expect(page.locator('#feedbackBox')).toBeVisible({ timeout: 90_000 });
  await expect(page.locator('#feedbackContent')).toContainText('Öncelikli', { timeout: 90_000 });

  // Next question
  await expect(page.locator('#okNextBtn')).toBeEnabled({ timeout: 30_000 });
  await page.click('#okNextBtn');

  await expect(page.locator('#chipIndex')).toContainText('Soru 2/2');
});
