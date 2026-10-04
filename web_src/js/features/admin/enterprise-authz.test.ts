import {initEnterpriseAuthz} from './enterprise-authz.ts';

afterEach(() => { document.body.replaceChildren(); vi.restoreAllMocks() });

test('permission rows retain different conditions and renumber on removal', () => {
  document.body.innerHTML = `<main class="enterprise-authz"><form data-authz-role-form><input name="permission_count" value="0"><select name="permissions_mode"><option value="replace">replace</option><option value="unchanged">unchanged</option></select><div data-authz-permissions></div><button type="button" data-authz-add-permission>Add</button></form><template data-authz-permission-template><fieldset data-authz-permission><div class="field"><label for="old">Action</label><select data-authz-field="action"><option>repo.push_branch</option></select></div><div class="field"><label>Branch</label><textarea data-authz-field="branch"></textarea></div><button type="button" data-authz-remove-permission>Remove</button></fieldset></template></main>`;
  initEnterpriseAuthz();
  const add = document.querySelector<HTMLButtonElement>('[data-authz-add-permission]')!;
  add.click(); add.click();
  const fields = document.querySelectorAll<HTMLTextAreaElement>('[data-authz-field="branch"]');
  fields[0].value = 'main'; fields[1].value = 'release/*';
  document.querySelector<HTMLButtonElement>('[data-authz-remove-permission]')!.click();
  expect(document.querySelector<HTMLInputElement>('[name="permission_count"]')!.value).toBe('1');
  expect(document.querySelector<HTMLTextAreaElement>('[name="permission_0_branch"]')!.value).toBe('release/*');
  expect(document.querySelector('label')!.htmlFor).toBe('authz-permission-0-action');
});

test('canceling a destructive form does not disable its buttons', () => {
  document.body.innerHTML = `<main class="enterprise-authz"><form method="post" data-authz-confirm="Really remove?"><button type="submit">Remove</button></form></main>`;
  const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false);
  initEnterpriseAuthz();
  const form = document.querySelector('form')!;
  const event = new Event('submit', {cancelable: true});
  form.dispatchEvent(event);
  expect(confirm).toHaveBeenCalledWith('Really remove?');
  expect(event.defaultPrevented).toBe(true);
  expect(document.querySelector('button')!.disabled).toBe(false);
});

test('picker selects names safely and invalidates edited or cleared selections', async () => {
  document.body.innerHTML = `<main class="enterprise-authz"><div data-authz-config data-authz-root="/-/admin/enterprise/authz" data-authz-scope-type="repo" data-authz-scope-id="1" data-loading="Loading" data-error="Failed" data-empty="Empty" data-next="Next" data-previous="Previous" data-choose="Choose an object"></div><form><select name="scope_type"><option value="repo">repo</option></select><input name="scope_id" type="hidden"><div data-authz-picker><input id="target" type="hidden" value="5"><input data-authz-selector="scope" data-authz-target="target" value="Old repository" required><div data-authz-selected>Old repository</div><button type="button" data-authz-clear>Clear</button><div data-authz-results></div></div></form></main>`;
  const fetch = vi.spyOn(window, 'fetch').mockResolvedValue(Response.json({items: [{id: 7, label: '<script>alert(1)</script>'}], total: 1, page: 1, limit: 20}));
  initEnterpriseAuthz();
  const input = document.querySelector<HTMLInputElement>('[data-authz-selector]')!;
  const target = document.querySelector<HTMLInputElement>('#target')!;
  const results = document.querySelector<HTMLElement>('[data-authz-results]')!;
  input.value = 'repository'; input.dispatchEvent(new Event('input'));
  expect(target.value).toBe('');
  expect(input.checkValidity()).toBe(false);
  await vi.waitFor(() => expect(results.querySelector('button')!.textContent).toBe('<script>alert(1)</script>'));
  expect(results.querySelector('script')).toBeNull();
  results.querySelector('button')!.click();
  expect(target.value).toBe('7');
  expect(document.querySelector('[data-authz-selected]')!.textContent).toBe('<script>alert(1)</script>');
  expect(input.checkValidity()).toBe(true);
  fetch.mockReturnValue(new Promise(() => {}));
  input.value = 'pending'; input.dispatchEvent(new Event('input'));
  expect(target.value).toBe('');
  expect(results.getAttribute('aria-busy')).toBe('true');
  document.querySelector<HTMLButtonElement>('[data-authz-clear]')!.click();
  expect(input.value).toBe('');
  expect(target.value).toBe('');
  expect(results.hasAttribute('aria-busy')).toBe(false);
  expect(results.textContent).toBe('');
  expect(input.checkValidity()).toBe(false);
});

test('date controls render and submit browser-local instants without shifting unchanged values', () => {
  document.body.innerHTML = `<main class="enterprise-authz"><form><div data-authz-timezone></div><input id="since-value" name="since" type="hidden" value="1767225600"><input type="datetime-local" step="1" data-authz-time="since-value" data-error="Invalid local date" disabled><button>Filter</button></form></main>`;
  initEnterpriseAuthz();
  const input = document.querySelector<HTMLInputElement>('[data-authz-time]')!;
  const hidden = document.querySelector<HTMLInputElement>('#since-value')!;
  const date = new Date(1767225600000);
  const local = new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, 19);
  expect(input.value).toBe(local.replace(/:00$/, ''));
  expect(input.disabled).toBe(false);
  expect(document.querySelector('[data-authz-timezone]')!.textContent).toBe(new Intl.DateTimeFormat().resolvedOptions().timeZone);
  input.dispatchEvent(new Event('change'));
  expect(hidden.value).toBe('1767225600');
  input.value = '2026-07-01T12:34:56'; input.dispatchEvent(new Event('input'));
  expect(hidden.value).toBe(String(new Date('2026-07-01T12:34:56').getTime() / 1000));
  expect(input.checkValidity()).toBe(true);
  input.value = ''; input.dispatchEvent(new Event('input'));
  expect(hidden.value).toBe('');
});
