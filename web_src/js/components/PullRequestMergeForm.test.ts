import {createApp, h, nextTick} from 'vue';
import PullRequestMergeForm from './PullRequestMergeForm.vue';

function mountMergeForm(candidateDecision: string, canBypass = false, mode = 'enforce', manual = false) {
  const root = document.createElement('div');
  document.body.append(root);
  const app = createApp({render: () => h(PullRequestMergeForm, {mergeFormProps: {
    allOverridableChecksOk: true, baseLink: '/user/repo/pulls/1', canMergeNow: true,
    defaultDeleteBranchAfterMerge: false, defaultMergeMessage: '', defaultMergeStyle: manual ? 'manually-merged' : 'merge', emptyCommit: false,
    hasPendingPullRequestMerge: false, hasPendingPullRequestMergeTip: '', isPullBranchDeletable: false,
    mergeMessageFieldPlaceHolder: '', pullHeadCommitID: 'a'.repeat(40),
    mergeStyles: [{name: manual ? 'manually-merged' : 'merge', allowed: true, textDoMerge: 'Merge', hideAutoMerge: false}],
    textAutoMergeButtonWhenSucceed: 'when ready', textAutoMergeCancelSchedule: 'Cancel schedule', textAutoMergeWhenSucceed: 'Auto merge',
    textCancel: 'Cancel', textClearMergeMessage: 'Clear', textClearMergeMessageHint: '', textDeleteBranch: 'Delete branch', textMergeCommitId: 'Commit',
    mergeGate: {
      mode, previewStyle: manual ? 'manually-merged' : 'merge', previewUrl: '/user/repo/pulls/1/merge_gate',
      preview: {mode, candidate_decision: candidateDecision, can_bypass: canBypass, can_schedule: true, reasons: [{code: 'required_check', state: 'failed', message_key: 'repo.merge_gate.reason.required_check'}]},
      descriptors: [{code: 'required_check', message_key: 'repo.merge_gate.reason.required_check', text: '<script>check</script>', bypass_category: 'required_check'}],
      textTitle: 'Merge gate', textShadow: 'Candidate only', textUnknown: 'Unable to determine', textPreview: 'Rechecked before execution',
      textBypass: 'Request bypass', textReason: 'Reason', textCategories: 'Bypass categories',
    },
  }})});
  app.mount(root);
  afterEach(() => {app.unmount(); root.remove()});
  return root;
}

test('enforce error is not a passing merge and reason labels are escaped', async () => {
  const root = mountMergeForm('error');
  await nextTick();
  expect(root.textContent).toContain('Unable to determine');
  expect(root.textContent).toContain('<script>check</script>');
  expect(root.querySelector('script')).toBeNull();
  expect(root.querySelector<HTMLButtonElement>('.merge-button > button')!.disabled).toBe(true);
  expect(root.querySelector('[data-merge-gate-bypass]')).toBeNull();
});

test('bypass is explicit and carries required reason and selected categories', async () => {
  const root = mountMergeForm('deny', true);
  await nextTick();
  root.querySelector<HTMLButtonElement>('[data-merge-gate-bypass]')!.click();
  await nextTick();
  expect(root.querySelector<HTMLInputElement>('[name=force_merge]')!.value).toBe('true');
  expect(root.querySelector<HTMLTextAreaElement>('[name=bypass_reason]')!.required).toBe(true);
  expect(root.querySelector<HTMLInputElement>('[name=bypass_categories]')!.value).toBe('required_check');
  expect(root.querySelector<HTMLButtonElement>('[type=submit][name=do]')!.disabled).toBe(true);
});

test('shadow only explains candidate blockers and preserves native merge', async () => {
  const root = mountMergeForm('deny', true, 'shadow');
  await nextTick();
  expect(root.textContent).toContain('Candidate only');
  expect(root.querySelector<HTMLButtonElement>('.merge-button > button')!.disabled).toBe(false);
  expect(root.querySelector('[data-merge-gate-bypass]')).toBeNull();
});

test('auto merge clears bypass request and Escape dismisses its form', async () => {
  const root = mountMergeForm('deny', true);
  await nextTick();
  root.querySelector<HTMLButtonElement>('[data-merge-gate-bypass]')!.click();
  await nextTick();
  root.querySelector('form')!.dispatchEvent(new KeyboardEvent('keydown', {key: 'Escape', bubbles: true}));
  await nextTick();
  expect(root.querySelector('form')).toBeNull();
  root.querySelector<HTMLButtonElement>('.auto-merge-small')!.click();
  await nextTick();
  root.querySelector<HTMLButtonElement>('.merge-button > button')!.click();
  await nextTick();
  expect(root.querySelector<HTMLInputElement>('[name=force_merge]')!.value).toBe('false');
  expect(root.querySelector<HTMLInputElement>('[name=merge_when_checks_succeed]')!.value).toBe('true');
  expect(root.querySelector('[name=bypass_reason]')).toBeNull();
  expect(root.querySelector<HTMLButtonElement>('[type=submit][name=do]')!.disabled).toBe(false);
});

test('manual proof input stays reachable while unknown cannot be submitted', async () => {
  const root = mountMergeForm('error', false, 'enforce', true);
  await nextTick();
  expect(root.querySelector<HTMLButtonElement>('.merge-button > button')!.disabled).toBe(false);
  root.querySelector<HTMLButtonElement>('.merge-button > button')!.click();
  await nextTick();
  expect(root.querySelector('[name=merge_commit_id]')).not.toBeNull();
  expect(root.querySelector<HTMLButtonElement>('[type=submit][name=do]')!.disabled).toBe(true);
});
