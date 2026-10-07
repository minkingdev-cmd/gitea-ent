import {env} from 'node:process';
import {test, expect} from '@playwright/test';
import type {APIRequestContext, Page} from '@playwright/test';
import {apiCreateFiles, apiCreatePR, apiCreateRepo, apiHeaders, assertNoJsError, login, randomString} from './utils.ts';

async function prepareGate(page: Page, request: APIRequestContext) {
  const owner = env.GITEA_TEST_E2E_USER;
  const repo = `e2e-gate-${randomString(8)}`;
  const root = `/api/v1/repos/${owner}/${repo}`;
  const setup = (async () => {
    await apiCreateRepo(request, {name: repo});
    await apiCreateFiles(request, owner, repo, [{path: 'feat.txt', content: 'feature\n'}], {branch: 'main', newBranch: 'feat'});
    const policy = await request.put(`${root}/enterprise/authz/features/feature.gitleaks_scan`, {
      headers: apiHeaders(),
      data: {state: 'required', config: {check_contexts: ['security/e2e-private-context']}, expected_revision: 0},
    });
    expect(policy.status(), await policy.text()).toBe(200);
    return apiCreatePR(request, owner, repo, 'feat', 'main', 'enterprise gate test');
  })();
  const [index] = await Promise.all([setup, login(page)]);
  await page.goto(`/${owner}/${repo}/pulls/${index}`, {waitUntil: 'commit'});
  await expect(page.getByText('Enterprise merge gate', {exact: true})).toBeVisible();
  await expect(page.getByText('A required check has not succeeded.', {exact: true})).toBeVisible();
  await expect(page.getByRole('button', {name: 'Create merge commit', exact: true}).first()).toBeDisabled();
  await expect(page.getByText('security/e2e-private-context', {exact: true})).toHaveCount(0);
  return {root, index};
}

async function assertMerged(page: Page, request: APIRequestContext, root: string, index: number) {
  await expect(page.getByText(/successfully merged/i)).toBeVisible();
  const merged = await request.get(`${root}/pulls/${index}`, {headers: apiHeaders()});
  expect((await merged.json()).merged).toBe(true);
  await assertNoJsError(page);
}

if (env.GITEA_TEST_E2E_MERGE_GATE === 'enforce') {
  test('enterprise merge rejects forged bypass submissions before writing', async ({page, request}) => {
    const {root, index} = await prepareGate(page, request);
    const before = await request.get(`${root}/branches/main`, {headers: apiHeaders()});
    const sha = (await before.json()).commit.id;
    const mergeURL = new URL(page.url());
    mergeURL.pathname += '/merge';
    const crossOrigin = await page.request.post(mergeURL.href, {
      headers: {Origin: 'https://cross-site.invalid', 'Sec-Fetch-Site': 'cross-site'},
      form: {do: 'merge', force_merge: 'true', bypass_reason: 'Forged cross-site request', bypass_categories: 'required_check'},
    });
    expect(crossOrigin.status()).toBe(403);
    const missingReason = await request.post(`${root}/pulls/${index}/merge`, {
      headers: apiHeaders(), data: {do: 'merge', force_merge: true, bypass_categories: ['required_check']},
    });
    expect(missingReason.status()).toBe(422);
    const unknownCategory = await request.post(`${root}/pulls/${index}/merge`, {
      headers: apiHeaders(), data: {do: 'merge', force_merge: true, bypass_reason: 'An explicit reason', bypass_categories: ['skip_everything']},
    });
    expect(unknownCategory.status()).toBe(422);
    const autoBypass = await request.post(`${root}/pulls/${index}/merge`, {
      headers: apiHeaders(), data: {do: 'merge', merge_when_checks_succeed: true, force_merge: true, bypass_reason: 'An explicit reason', bypass_categories: ['required_check']},
    });
    expect(autoBypass.status()).toBe(422);
    const pr = await request.get(`${root}/pulls/${index}`, {headers: apiHeaders()});
    expect((await pr.json()).merged).toBe(false);
    const after = await request.get(`${root}/branches/main`, {headers: apiHeaders()});
    expect((await after.json()).commit.id).toBe(sha);
  });

  test('enterprise merge box consumes a current successful check', async ({page, request}) => {
    const {root, index} = await prepareGate(page, request);
    const pr = await request.get(`${root}/pulls/${index}`, {headers: apiHeaders()});
    expect(pr.status()).toBe(200);
    const head = (await pr.json()).head.sha;
    const status = await request.post(`${root}/statuses/${head}`, {
      headers: apiHeaders(),
      data: {context: 'security/e2e-private-context', state: 'success'},
    });
    expect(status.status(), await status.text()).toBe(201);
    await page.reload({waitUntil: 'commit'});
    await page.getByRole('button', {name: 'Create merge commit', exact: true}).first().click();
    await page.locator('form.form-fetch-action').getByRole('button', {name: 'Create merge commit', exact: true}).click();
    await assertMerged(page, request, root, index);
  });

  test('enterprise merge box requires an explicit limited bypass', async ({page, request}) => {
    const {root, index} = await prepareGate(page, request);
    await page.getByRole('button', {name: 'Request limited bypass', exact: true}).click();
    const form = page.locator('form.form-fetch-action');
    const submit = form.getByRole('button', {name: 'Create merge commit', exact: true});
    await expect(submit).toBeDisabled();
    await form.getByRole('checkbox', {name: 'A required check has not succeeded.', exact: true}).check();
    await expect(submit).toBeDisabled();
    const reason = page.getByLabel('Required bypass reason', {exact: true});
    await reason.focus();
    await expect(reason).toBeFocused();
    await reason.fill('Approved isolated test exception <script>window.gateInjected = true</script>');
    await expect(submit).toBeEnabled();
    await submit.focus();
    await expect(submit).toBeFocused();
    await page.keyboard.press('Enter');
    await assertMerged(page, request, root, index);
    expect(await page.evaluate(() => Object.hasOwn(window, 'gateInjected'))).toBe(false);
  });
}
