import {GET} from '../../modules/fetch.ts';

type SelectorResult = {items: {id: number, label: string, context?: string}[], total: number, limit: number, page: number};

export function initEnterpriseAuthz(): void {
  const page = document.querySelector<HTMLElement>('.enterprise-authz');
  if (!page || page.getAttribute('data-authz-initialized')) return;
  page.setAttribute('data-authz-initialized', 'true');
  for (const label of page.querySelectorAll<HTMLElement>('[data-authz-timezone]')) label.textContent = new Intl.DateTimeFormat().resolvedOptions().timeZone;
  for (const input of page.querySelectorAll<HTMLInputElement>('[data-authz-time]')) {
    const hidden = page.querySelector<HTMLInputElement>(`#${input.getAttribute('data-authz-time')!}`)!;
    const localValue = (date: Date) => new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, 19);
    if (hidden.value) input.value = localValue(new Date(Number(hidden.value) * 1000));
    const originalLocal = input.value;
    const originalInstant = hidden.value;
    input.disabled = false;
    const sync = () => {
      input.setCustomValidity('');
      if (!input.value && !input.validity.badInput) {
        hidden.value = '';
        return;
      }
      const date = new Date(input.value);
      const canonicalLocal = input.value.length === 16 ? `${input.value}:00` : input.value;
      if (!Number.isFinite(date.getTime()) || date.getTime() < 0 || date.getTime() / 1000 > 253402300799 || localValue(date) !== canonicalLocal) {
        hidden.value = '';
        input.setCustomValidity(input.getAttribute('data-error')!);
        return;
      }
      hidden.value = input.value === originalLocal ? originalInstant : String(date.getTime() / 1000);
    };
    input.addEventListener('input', sync);
    input.addEventListener('change', sync);
    input.form!.addEventListener('submit', (event) => {
      sync();
      if (!input.checkValidity()) event.preventDefault();
    });
  }
  const role = page.querySelector<HTMLFormElement>('[data-authz-role-form]');
  if (role) {
    const list = role.querySelector<HTMLElement>('[data-authz-permissions]')!;
    const renumber = () => {
      const rows = list.querySelectorAll<HTMLElement>('[data-authz-permission]');
      role.querySelector<HTMLInputElement>('[name="permission_count"]')!.value = String(rows.length);
      rows.forEach((row, index) => {
        for (const field of row.querySelectorAll<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>('[data-authz-field]')) {
          const key = field.getAttribute('data-authz-field')!;
          field.name = `permission_${index}_${key}`;
          field.id = `authz-permission-${index}-${key}`;
          field.parentElement!.querySelector('label')!.htmlFor = field.id;
        }
      });
    };
    role.querySelector('[data-authz-add-permission]')!.addEventListener('click', () => {
      const template = page.querySelector<HTMLTemplateElement>('[data-authz-permission-template]')!;
      list.append(template.content.cloneNode(true));
      renumber();
      list.lastElementChild!.querySelector<HTMLSelectElement>('select')!.focus();
    });
    list.addEventListener('click', (event) => {
      const source = (event.target as HTMLElement).closest('[data-authz-source]');
      if (source) {
        const field = source.closest('[data-authz-permission]')!.querySelector<HTMLTextAreaElement>('[data-authz-field="sources"]')!;
        const value = source.getAttribute('data-authz-source')!;
        const sources = field.value ? field.value.split('\n') : [];
        if (!sources.includes(value)) sources.push(value);
        field.value = sources.join('\n'); field.focus();
        return;
      }
      const button = (event.target as HTMLElement).closest('[data-authz-remove-permission]');
      if (!button) return;
      button.closest('[data-authz-permission]')!.remove();
      renumber();
      role.querySelector<HTMLButtonElement>('[data-authz-add-permission]')!.focus();
    });
    renumber();
  }
  for (const form of page.querySelectorAll<HTMLFormElement>('form[method="post"]')) {
    form.addEventListener('submit', (event) => {
      if (form.getAttribute('data-authz-confirm') && !window.confirm(form.getAttribute('data-authz-confirm')!)) {
        event.preventDefault();
        return;
      }
      for (const button of form.querySelectorAll<HTMLButtonElement>('button[type="submit"]')) button.disabled = true;
      form.setAttribute('aria-busy', 'true');
    });
  }
  const config = page.querySelector<HTMLElement>('[data-authz-config]');
  if (!config) return;
  const scopeType = page.querySelector<HTMLSelectElement>('[name="scope_type"]')!;
  const scopeID = page.querySelector<HTMLInputElement>('[name="scope_id"]')!;
  const scopeSearch = page.querySelector<HTMLInputElement>('[data-authz-selector="scope"]')!;
  const changeScope = () => {
    scopeID.disabled = scopeType.value === 'system';
    scopeSearch.required = !scopeID.disabled;
    scopeSearch.disabled = scopeID.disabled;
  };
  scopeType.addEventListener('change', () => {
    changeScope();
    scopeSearch.dispatchEvent(new Event('ce-authz-clear'));
  });
  changeScope();
  const subjectType = page.querySelector<HTMLSelectElement>('[data-authz-subject-type]');
  if (subjectType) {
    const input = page.querySelector<HTMLInputElement>('#authz-binding-subject-id-search')!;
    subjectType.addEventListener('change', () => {
      input.setAttribute('data-authz-selector', subjectType.value);
      input.dispatchEvent(new Event('ce-authz-clear'));
    });
  }
  for (const input of page.querySelectorAll<HTMLInputElement>('[data-authz-selector]')) {
    const picker = input.closest<HTMLElement>('[data-authz-picker]')!;
    const results = picker.querySelector<HTMLElement>('[data-authz-results]')!;
    const selected = picker.querySelector<HTMLElement>('[data-authz-selected]')!;
    const context = picker.querySelector<HTMLElement>('[data-authz-selected-context]');
    const clear = picker.querySelector<HTMLButtonElement>('[data-authz-clear]')!;
    const target = picker.querySelector<HTMLInputElement>(`#${CSS.escape(input.getAttribute('data-authz-target')!)}`)!;
    let controller: AbortController | undefined;
    let sequence = 0;
    let suppressFocus = false;
    const validate = () => {
      input.setCustomValidity(!input.disabled && !target.value && (input.required || Boolean(input.value.trim())) ? config.getAttribute('data-choose')! : '');
      clear.disabled = !target.value && !input.value && !selected.textContent;
    };
    const close = () => {
      if (controller) controller.abort();
      sequence++;
      results.replaceChildren();
      results.removeAttribute('aria-busy');
      input.setAttribute('aria-expanded', 'false');
    };
    const invalidate = () => {
      target.value = '';
      selected.textContent = '';
      if (context) context.textContent = '';
      validate();
    };
    const clearSelection = () => {
      close();
      input.value = '';
      invalidate();
    };
    const focusInput = () => {suppressFocus = true; input.focus(); suppressFocus = false};
    const search = async (pageNumber = 1) => {
      close();
      if (input.disabled) return;
      let kind = input.getAttribute('data-authz-selector')!;
      const isScope = kind === 'scope';
      if (isScope) kind = scopeType.value;
      if (kind === 'system') return;
      controller = new AbortController();
      const signal = controller.signal;
      const current = sequence;
      input.setAttribute('aria-expanded', 'true');
      results.textContent = config.getAttribute('data-loading')!;
      results.setAttribute('aria-busy', 'true');
      const params = new URLSearchParams({q: input.value.trim(), page: String(pageNumber), limit: '20', scope_type: isScope ? 'system' : config.getAttribute('data-authz-scope-type')!, scope_id: isScope ? '0' : config.getAttribute('data-authz-scope-id')!});
      try {
        const response = await GET(`${config.getAttribute('data-authz-root')}/selectors/${kind}?${params}`, {signal});
        if (!response.ok) throw new Error('selector_failed');
        const data = await response.json() as SelectorResult;
        if (current !== sequence) return;
        results.replaceChildren();
        if (!data.items.length) results.textContent = config.getAttribute('data-empty')!;
        for (const item of data.items) {
          const option = document.createElement('button');
          option.type = 'button'; option.className = 'ui small button';
          option.setAttribute('role', 'option');
          option.setAttribute('aria-selected', 'false');
          const label = document.createElement('span'); label.textContent = item.label; option.append(label);
          if (item.context) {
            const caption = document.createElement('small'); caption.className = 'tw-block tw-text-text-light'; caption.textContent = item.context; option.append(caption);
          }
          option.addEventListener('click', () => {
            target.value = String(item.id);
            input.value = item.label;
            selected.textContent = item.label;
            if (context) context.textContent = item.context || '';
            close(); validate(); input.focus();
          });
          results.append(option);
        }
        const pager = (label: string, number: number) => {
          const button = document.createElement('button');
          button.type = 'button'; button.className = 'ui small button'; button.textContent = label;
          button.addEventListener('click', () => {search(number)});
          results.append(button);
        };
        if (data.page > 1) pager(config.getAttribute('data-previous')!, data.page - 1);
        if (data.page * data.limit < data.total) pager(config.getAttribute('data-next')!, data.page + 1);
      } catch {
        if (current === sequence && !signal.aborted) results.textContent = config.getAttribute('data-error')!;
      } finally {
        if (current === sequence) results.removeAttribute('aria-busy');
      }
    };
    if (picker.hasAttribute('data-authz-unavailable')) {target.value = ''; input.value = ''}
    validate();
    input.addEventListener('input', () => {invalidate(); if (input.value.trim()) search(); else close();});
    input.addEventListener('focus', () => {if (!suppressFocus && !target.value) search();});
    input.addEventListener('ce-authz-clear', clearSelection);
    clear.addEventListener('click', () => {clearSelection(); focusInput()});
    input.addEventListener('keydown', (event) => {
      if (event.key === 'Enter') event.preventDefault();
      else if (event.key === 'Escape') close();
      else if (event.key === 'ArrowDown') {
        event.preventDefault();
        const first = results.querySelector<HTMLButtonElement>('[role="option"]');
        if (first) first.focus(); else search();
      }
    });
    results.addEventListener('keydown', (event) => {
      if (event.key === 'Escape') {close(); focusInput(); return}
      if (event.key !== 'ArrowDown' && event.key !== 'ArrowUp') return;
      event.preventDefault();
      const options = [...results.querySelectorAll<HTMLButtonElement>('[role="option"]')];
      const index = options.indexOf(document.activeElement as HTMLButtonElement);
      if (options.length) options[(index + (event.key === 'ArrowDown' ? 1 : -1) + options.length) % options.length].focus();
    });
    input.form!.addEventListener('submit', (event) => {validate(); if (!input.checkValidity()) {event.preventDefault(); input.reportValidity()}});
  }
}
