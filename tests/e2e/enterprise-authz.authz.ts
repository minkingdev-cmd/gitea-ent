import {test, expect} from '@playwright/test';
import {env} from 'node:process';
import {login, randomString} from './utils.ts';

// 仅在已启用企业授权的隔离验收实例执行。
test('enterprise authorization administration end-to-end', async ({page}, testInfo) => {
  await login(page);
  await page.goto('/-/admin/enterprise/authz/scopes/repo/1/roles');
  const repositoryPath = env.GITEA_TEST_E2E_AUTHZ_REPO_PATH || '/e2e-admin/authz-repository';
  await page.getByRole('combobox', {name: 'Find an organization or repository', exact: true}).fill(repositoryPath.split('/').at(-1)!);
  const scopeOption = page.getByRole('option', {name: repositoryPath.slice(1), exact: true});
  await expect(scopeOption).toBeVisible();
  await page.getByRole('combobox', {name: 'Find an organization or repository', exact: true}).press('ArrowDown');
  await expect(scopeOption).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(page.locator('input[name="scope_id"]')).toHaveAttribute('type', 'hidden');
  await page.getByRole('button', {name: 'Switch scope', exact: true}).click();
  const roleName = `authz-${randomString(8)}`;
  await page.getByRole('link', {name: 'Create role', exact: true}).click();
  await page.getByLabel('Name', {exact: true}).focus();
  await page.keyboard.insertText(roleName);
  await page.getByRole('button', {name: 'Add permission', exact: true}).click();
  await expect(page.getByLabel('Action', {exact: true})).toBeFocused();
  await page.getByLabel('Action', {exact: true}).selectOption('repo.push_branch');
  await page.getByLabel('Branch patterns (one per line)').fill('release/*');
  await page.getByLabel('Path patterns (one per line)').fill('docs/**');
  await page.getByRole('button', {name: 'Diagnostic only', exact: true}).click();
  await page.getByRole('button', {name: 'Save role', exact: true}).click();
  await expect(page.getByLabel('Name', {exact: true})).toHaveValue(roleName);
  const roleID = page.url().split('/').at(-1)!;
  await expect(page.getByLabel('Request sources (one per line)')).toHaveValue('diagnostic');
  await page.screenshot({path: testInfo.outputPath('enterprise-authz-role-light.png'), fullPage: true});
  await page.getByRole('link', {name: 'Subject bindings', exact: true}).click();
  const subjectName = env.GITEA_TEST_E2E_AUTHZ_SUBJECT_NAME || 'e2e-member';
  await page.getByRole('combobox', {name: 'Search subjects', exact: true}).fill(subjectName);
  await page.getByRole('option', {name: subjectName, exact: true}).click();
  await page.getByRole('combobox', {name: 'Search available roles', exact: true}).fill(roleName);
  await page.getByRole('option', {name: new RegExp(`^${roleName}`)}).click();
  await page.getByRole('button', {name: 'Bind role', exact: true}).click();
  await expect(page.getByRole('row').filter({hasText: roleName})).toHaveCount(1);
  await page.getByRole('link', {name: 'Effective permissions & diagnostic', exact: true}).click();
  const diagnostic = page.locator('form[method="post"]');
  await diagnostic.getByRole('combobox', {name: 'Find a user', exact: true}).fill(subjectName);
  await diagnostic.getByRole('option', {name: subjectName, exact: true}).click();
  await page.getByLabel('Action', {exact: true}).selectOption('repo.push_branch');
  await page.getByLabel('Branch', {exact: true}).fill('release/v1');
  await page.getByLabel('Complete paths, one per line').fill('docs/public.md');
  await page.getByRole('button', {name: 'Diagnose action', exact: true}).click();
  await expect(page.locator('[data-candidate-decision]')).toHaveAttribute('data-candidate-decision', 'allow');
  await expect(page.locator('[data-condition-result="matched"]')).toHaveCount(1);
  await page.screenshot({path: testInfo.outputPath('enterprise-authz-diagnostic-light.png'), fullPage: true});
  await page.goto(env.GITEA_TEST_E2E_AUTHZ_REPO_PATH || '/e2e-admin/authz-repository');
  await page.goto('/-/admin/enterprise/authz/scopes/repo/1/decisions');
  await page.getByRole('combobox', {name: 'User or actor', exact: true}).fill(env.GITEA_TEST_E2E_USER || 'e2e-admin');
  await page.getByRole('option', {name: env.GITEA_TEST_E2E_USER || 'e2e-admin', exact: true}).click();
  await page.getByRole('combobox', {name: 'Repository', exact: true}).fill(repositoryPath.split('/').at(-1)!);
  await page.getByRole('option', {name: repositoryPath.slice(1), exact: true}).click();
  await page.getByLabel('From (local time)', {exact: true}).fill('2020-01-01T00:00');
  await page.getByRole('button', {name: 'Filter', exact: true}).click();
  await expect(page.getByLabel('From (local time)', {exact: true})).toHaveValue('2020-01-01T00:00');
  await expect(page.locator('#authz-history-actor-selected')).toHaveText(env.GITEA_TEST_E2E_USER || 'e2e-admin');
  await page.screenshot({path: testInfo.outputPath('enterprise-authz-filters-light.png'), fullPage: true});
  await page.getByRole('link', {name: 'View details', exact: true}).first().click();
  await page.getByText('Technical identifiers', {exact: true}).click();
  await expect(page.getByText('Operation ID', {exact: true})).toBeVisible();
  await expect(page.getByText('Observation ID', {exact: true})).toBeVisible();
  await page.emulateMedia({colorScheme: 'dark'});
  await expect.poll(() => page.locator(':root').evaluate((el) => el.ownerDocument.defaultView!.getComputedStyle(el).getPropertyValue('--is-dark-theme').trim())).toBe('true');
  await page.screenshot({path: testInfo.outputPath('enterprise-authz-history-dark.png'), fullPage: true});
  await page.goto(`/-/admin/enterprise/authz/scopes/repo/1/roles/${roleID}`);
  await page.getByRole('link', {name: 'Copy into current scope', exact: true}).click();
  await page.getByLabel('Name', {exact: true}).fill(`${roleName}-copy`);
  await page.getByRole('button', {name: 'Save role', exact: true}).click();
  const copyID = page.url().split('/').at(-1)!;
  await page.getByLabel(/I confirm deleting/).check();
  await page.getByRole('button', {name: 'Delete role', exact: true}).click();
  await expect(page.getByRole('link', {name: `${roleName}-copy`, exact: true})).toHaveCount(0);
  await page.goto('/-/admin/enterprise/authz/scopes/repo/1/bindings');
  page.once('dialog', (dialog) => dialog.dismiss());
  await page.getByRole('row').filter({hasText: roleName}).getByRole('button', {name: 'Remove binding', exact: true}).click();
  await expect(page.getByRole('row').filter({hasText: roleName})).toHaveCount(1);
  page.once('dialog', (dialog) => dialog.accept());
  await page.getByRole('row').filter({hasText: roleName}).getByRole('button', {name: 'Remove binding', exact: true}).click();
  await expect(page.getByRole('row').filter({hasText: roleName})).toHaveCount(0);
  await page.goto(`/-/admin/enterprise/authz/scopes/repo/1/roles/${roleID}`);
  await page.getByLabel('Name', {exact: true}).fill(`${roleName}-updated`);
  await page.getByRole('button', {name: 'Save role', exact: true}).click();
  await expect(page.locator('form[data-authz-role-form] [name="expected_revision"]')).toHaveValue('2');
  await page.getByLabel(/I confirm deleting/).check();
  await page.getByRole('button', {name: 'Delete role', exact: true}).click();
  await expect(page.getByRole('link', {name: `${roleName}-updated`, exact: true})).toHaveCount(0);
  expect(copyID).not.toBe(roleID);
});

for (const [timezoneId, winter, summer] of [
  ['Asia/Shanghai', '2026-01-01T08:00', '2026-07-01T08:00'],
  ['America/New_York', '2025-12-31T19:00', '2026-06-30T20:00'],
]) {
  test.describe(timezoneId, () => {
    test.use({timezoneId});
    test('history dates round-trip local time across seasonal offsets', async ({page}) => {
      await login(page);
      await page.goto('/-/admin/enterprise/authz/scopes/system/decisions?since=1767225600&until=1782864000');
      await expect(page.getByLabel('From (local time)', {exact: true})).toHaveValue(winter);
      await expect(page.getByLabel('Until (local time)', {exact: true})).toHaveValue(summer);
      await expect(page.locator('[data-authz-timezone]')).toHaveText(timezoneId);
      await page.getByRole('button', {name: 'Filter', exact: true}).click();
      expect(new URL(page.url()).searchParams.get('since')).toBe('1767225600');
      expect(new URL(page.url()).searchParams.get('until')).toBe('1782864000');
      const input = page.getByLabel('From (local time)', {exact: true});
      await input.fill('2026-07-01T12:34:56');
      const expected = await input.evaluate((el: HTMLInputElement) => String(new Date(el.value).getTime() / 1000));
      await expect(page.locator('[name="since"]')).toHaveValue(expected);
      if (timezoneId === 'America/New_York') {
        await input.evaluate((el: HTMLInputElement) => { el.value = '2026-03-08T02:30'; el.dispatchEvent(new Event('input', {bubbles: true})) });
        expect(await input.evaluate((el: HTMLInputElement) => el.checkValidity())).toBe(false);
        await expect(page.locator('[name="since"]')).toHaveValue('');
      }
      if (timezoneId === 'America/New_York') {
        await page.goto('/-/admin/enterprise/authz/scopes/system/decisions?since=1793514600');
        await expect(input).toHaveValue('2026-11-01T01:30');
        await page.getByRole('button', {name: 'Filter', exact: true}).click();
        expect(new URL(page.url()).searchParams.get('since')).toBe('1793514600');
      }
      await input.fill('');
      await expect(page.locator('[name="since"]')).toHaveValue('');
      await page.goto(env.GITEA_TEST_E2E_AUTHZ_REPO_PATH || '/e2e-admin/authz-repository');
      const now = Math.floor(Date.now() / 1000);
      await page.goto(`/-/admin/enterprise/authz/scopes/repo/1/decisions?since=${now - 60}&until=${now + 60}`);
      const recorded = page.locator('tbody relative-time').first();
      await expect(recorded).toBeVisible();
      const localRecorded = await recorded.evaluate((el) => new Intl.DateTimeFormat('en-US', {year: 'numeric', month: 'short', day: 'numeric', hour: 'numeric', minute: 'numeric', second: 'numeric'}).format(new Date(el.getAttribute('datetime')!)));
      await expect(recorded.locator('span[part="root"]')).toHaveText(localRecorded);
      await page.getByRole('button', {name: 'Filter', exact: true}).click();
      await expect(page.locator('tbody relative-time span[part="root"]').first()).toHaveText(localRecorded);
    });
  });
}
