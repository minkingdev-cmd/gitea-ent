<script lang="ts" setup>
import {computed, onMounted, onUnmounted, shallowRef, watch} from 'vue';
import SvgIcon from './SvgIcon.vue';
import {toggleElem} from '../utils/dom.ts';
import {GET} from '../modules/fetch.ts';

type MergeStyle = {
  name: string,
  allowed: boolean,
  textDoMerge: string,
  mergeTitleFieldText?: string,
  mergeMessageFieldText?: string,
  hideMergeMessageTexts?: boolean,
  hideAutoMerge: boolean,
};

type MergeGatePreview = {
  mode: string,
  candidate_decision: string,
  can_bypass: boolean,
  can_schedule: boolean,
  reasons: {code: string, state: string, message_key: string}[],
};

type MergeGate = {
  mode: string,
  preview?: MergeGatePreview,
  previewStyle: string,
  previewUrl: string,
  descriptors: {code: string, message_key: string, text: string, bypass_category: string}[],
  textTitle: string,
  textShadow: string,
  textUnknown: string,
  textPreview: string,
  textBypass: string,
  textReason: string,
  textCategories: string,
};

type MergeForm = {
  mergeGate?: MergeGate,
  allOverridableChecksOk: boolean,
  baseLink: string,
  canMergeNow: boolean,
  defaultDeleteBranchAfterMerge: boolean,
  defaultMergeMessage: string,
  defaultMergeStyle: string,
  emptyCommit: boolean,
  hasPendingPullRequestMerge: boolean,
  hasPendingPullRequestMergeTip: string,
  isPullBranchDeletable: boolean,
  mergeMessageFieldPlaceHolder: string,
  mergeStyles: MergeStyle[],
  pullHeadCommitID: string,
  textAutoMergeButtonWhenSucceed: string,
  textAutoMergeCancelSchedule: string,
  textAutoMergeWhenSucceed: string,
  textCancel: string,
  textClearMergeMessage: string,
  textClearMergeMessageHint: string,
  textDeleteBranch: string,
  textMergeCommitId: string,
};

const props = defineProps<{
  mergeFormProps: MergeForm,
}>();

const mergeStyleManuallyMerged = 'manually-merged';

const mergeForm = props.mergeFormProps;

const mergeTitleFieldValue = shallowRef<string | undefined>('');
const mergeMessageFieldValue = shallowRef<string | undefined>('');
const deleteBranchAfterMerge = shallowRef(false);
const autoMergeWhenSucceed = shallowRef(false);

const gatePreview = shallowRef(mergeForm.mergeGate?.preview);
const bypassRequested = shallowRef(false);
const bypassReason = shallowRef('');
const bypassCategories = shallowRef<string[]>([]);
const manualCommitID = shallowRef('');
const gateEnforce = mergeForm.mergeGate?.mode === 'enforce';
let previewRequest: AbortController | undefined;
const gateBypassAvailable = computed(() => gateEnforce && !autoMergeWhenSucceed.value && gatePreview.value?.candidate_decision === 'deny' && gatePreview.value.can_bypass);
const bypassChoices = computed(() => mergeForm.mergeGate?.descriptors.filter((entry) => entry.bypass_category && gatePreview.value?.reasons.some((reason) => reason.code === entry.code)) || []);
const gateSubmitAllowed = computed(() => {
  if (!gateEnforce) return true;
  const preview = gatePreview.value;
  if (!preview) return false;
  if (autoMergeWhenSucceed.value) return !bypassRequested.value && preview.can_schedule;
  if (!bypassRequested.value) return preview.candidate_decision === 'allow';
  return preview.can_bypass && preview.candidate_decision === 'deny' && bypassCategories.value.length > 0 && bypassReason.value.trim().length > 0 && new TextEncoder().encode(bypassReason.value.trim()).length <= 1024;
});

function reasonText(code: string) {
  return mergeForm.mergeGate!.descriptors.find((entry) => entry.code === code)?.text || mergeForm.mergeGate!.textUnknown;
}

async function refreshGatePreview() {
  if (!mergeForm.mergeGate) return;
  previewRequest?.abort();
  const request = new AbortController();
  previewRequest = request;
  gatePreview.value = undefined;
  bypassRequested.value = false;
  bypassReason.value = '';
  bypassCategories.value = [];
  const query = new URLSearchParams({style: mergeStyle.value, commit_id: manualCommitID.value});
  try {
    const response = await GET(`${mergeForm.mergeGate.previewUrl}?${query}`, {signal: request.signal});
    if (!response.ok || request !== previewRequest) return;
    const preview: MergeGatePreview = await response.json();
    if (request === previewRequest && ['allow', 'deny', 'error', 'bypass'].includes(preview.candidate_decision)) gatePreview.value = preview;
  } catch {
    // 无法取得预览时保持不可确定，不能沿用旧许可。
  }
}

watch(manualCommitID, refreshGatePreview);
watch(autoMergeWhenSucceed, () => {
  bypassRequested.value = false;
  bypassReason.value = '';
  bypassCategories.value = [];
});

const mergeStyle = shallowRef('');
const mergeStyleDetail = shallowRef<MergeStyle>({name: '', allowed: false, textDoMerge: '', hideAutoMerge: false});

const mergeStyleAllowedCount = shallowRef(0);

const showMergeStyleMenu = shallowRef(false);
const showActionForm = shallowRef(false);

const mergeButtonStyleClass = computed(() => {
  if (mergeStyle.value === mergeStyleManuallyMerged) return 'red';
  if (mergeForm.allOverridableChecksOk) return 'primary';
  return autoMergeWhenSucceed.value ? 'primary' : 'red';
});

const mergeSelectStyleClass = computed(() => {
  if (mergeForm.emptyCommit) return '';
  if (mergeStyle.value === mergeStyleManuallyMerged) return 'red';
  if (!mergeForm.allOverridableChecksOk) return 'red';
  return 'primary';
});

const forceMerge = computed(() => {
  if (gateEnforce) return !autoMergeWhenSucceed.value && bypassRequested.value;
  return mergeForm.canMergeNow && !mergeForm.allOverridableChecksOk;
});

watch(mergeStyle, (val, old) => {
  if (mergeForm.mergeGate && (old || val !== mergeForm.mergeGate.previewStyle)) void refreshGatePreview();
  mergeStyleDetail.value = mergeForm.mergeStyles.find((e) => e.name === val)!;
  for (const elem of document.querySelectorAll('[data-pull-merge-style]')) {
    toggleElem(elem, elem.getAttribute('data-pull-merge-style') === val);
  }
});

onMounted(() => {
  mergeStyleAllowedCount.value = mergeForm.mergeStyles.reduce((v, msd) => v + (msd.allowed ? 1 : 0), 0);

  let mergeStyle = mergeForm.mergeStyles.find((e) => e.allowed && e.name === mergeForm.defaultMergeStyle)?.name;
  if (!mergeStyle) mergeStyle = mergeForm.mergeStyles.find((e) => e.allowed)?.name;
  if (mergeStyle) switchMergeStyle(mergeStyle, !mergeForm.canMergeNow);

  document.addEventListener('mouseup', hideMergeStyleMenu);
});

onUnmounted(() => {
  document.removeEventListener('mouseup', hideMergeStyleMenu);
  previewRequest?.abort();
});

function hideMergeStyleMenu() {
  showMergeStyleMenu.value = false;
}

function toggleActionForm(show: boolean) {
  showActionForm.value = show;
  if (!show) return;
  deleteBranchAfterMerge.value = mergeForm.defaultDeleteBranchAfterMerge;
  mergeTitleFieldValue.value = mergeStyleDetail.value.mergeTitleFieldText;
  mergeMessageFieldValue.value = mergeStyleDetail.value.mergeMessageFieldText;
}

function switchMergeStyle(name: string, autoMerge = false) {
  mergeStyle.value = name;
  autoMergeWhenSucceed.value = gateEnforce && name === mergeStyleManuallyMerged ? false : autoMerge;
}

function clearMergeMessage() {
  mergeMessageFieldValue.value = mergeForm.defaultMergeMessage;
}
</script>

<template>
  <!--
  if this component is shown, either the user is an admin (can do a merge without checks), or they are a writer who has the permission to do a merge
  if the user is a writer and can't do a merge now (canMergeNow==false), then only show the Auto Merge for them
  How to test the UI manually:
  * Method 1: manually set some variables in pull.tmpl, eg: {{$notAllOverridableChecksOk = true}} {{$canMergeNow = false}}
  * Method 2: make a protected branch, then set state=pending/success :
    curl -X POST ${root_url}/api/v1/repos/${owner}/${repo}/statuses/${sha} \
      -H "accept: application/json" -H "authorization: Basic $base64_auth" -H "Content-Type: application/json" \
      -d '{"context": "test/context", "description": "description", "state": "${state}", "target_url": "http://localhost"}'
  -->
  <div @keydown.esc="showMergeStyleMenu = false; toggleActionForm(false)">
    <section v-if="mergeForm.mergeGate" class="ui message" :class="gatePreview?.candidate_decision === 'allow' ? 'info' : 'warning'" aria-live="polite">
      <strong>{{ mergeForm.mergeGate.textTitle }}</strong>
      <p v-if="mergeForm.mergeGate.mode === 'shadow'">{{ mergeForm.mergeGate.textShadow }}</p>
      <p v-if="!gatePreview || gatePreview.candidate_decision === 'error'">{{ mergeForm.mergeGate.textUnknown }}</p>
      <ul v-if="gatePreview?.reasons.length">
        <li v-for="reason in gatePreview.reasons" :key="`${reason.code}:${reason.state}:${reason.message_key}`">{{ reasonText(reason.code) }}</li>
      </ul>
      <p>{{ mergeForm.mergeGate.textPreview }}</p>
    </section>
    <!-- eslint-disable-next-line vue/no-v-html -->
    <div v-if="mergeForm.hasPendingPullRequestMerge" v-html="mergeForm.hasPendingPullRequestMergeTip" class="ui info message"/>

    <!-- another similar form is in pull.tmpl (manual merge)-->
    <form class="ui form form-fetch-action" v-if="showActionForm" :action="mergeForm.baseLink+'/merge'" method="post">
      <input type="hidden" name="head_commit_id" v-model="mergeForm.pullHeadCommitID">
      <input type="hidden" name="merge_when_checks_succeed" v-model="autoMergeWhenSucceed">
      <input type="hidden" name="force_merge" v-model="forceMerge">

      <template v-if="!mergeStyleDetail.hideMergeMessageTexts">
        <div class="field">
          <input type="text" name="merge_title_field" v-model="mergeTitleFieldValue">
        </div>
        <div class="field">
          <textarea name="merge_message_field" rows="5" :placeholder="mergeForm.mergeMessageFieldPlaceHolder" v-model="mergeMessageFieldValue"/>
          <template v-if="mergeMessageFieldValue !== mergeForm.defaultMergeMessage">
            <button @click.prevent="clearMergeMessage" class="btn tw-mt-1 tw-p-1 interact-fg" :data-tooltip-content="mergeForm.textClearMergeMessageHint">
              {{ mergeForm.textClearMergeMessage }}
            </button>
          </template>
        </div>
      </template>

      <div class="field" v-if="mergeStyle === mergeStyleManuallyMerged">
        <input type="text" name="merge_commit_id" :placeholder="mergeForm.textMergeCommitId" v-model="manualCommitID">
      </div>

      <fieldset v-if="gateEnforce && bypassRequested && !autoMergeWhenSucceed" class="tw-mb-4">
        <legend>{{ mergeForm.mergeGate!.textCategories }}</legend>
        <div class="field" v-for="entry in bypassChoices" :key="entry.code">
          <label class="flex-text-block">
            <input type="checkbox" name="bypass_categories" :value="entry.bypass_category" v-model="bypassCategories">
            {{ entry.text }}
          </label>
        </div>
        <div class="field">
          <label for="merge-gate-bypass-reason">{{ mergeForm.mergeGate!.textReason }}</label>
          <textarea id="merge-gate-bypass-reason" name="bypass_reason" v-model="bypassReason" required maxlength="1024" rows="3"/>
        </div>
      </fieldset>
      <div class="flex-text-block tw-gap-3">
        <button class="ui button" :class="mergeButtonStyleClass" type="submit" :disabled="!gateSubmitAllowed" name="do" :value="mergeStyle">
          {{ mergeStyleDetail.textDoMerge }}
          <template v-if="autoMergeWhenSucceed">
            {{ mergeForm.textAutoMergeButtonWhenSucceed }}
          </template>
        </button>

        <button v-if="gateBypassAvailable && !bypassRequested" data-merge-gate-bypass type="button" class="ui red button" @click="bypassRequested = true">
          {{ mergeForm.mergeGate!.textBypass }}
        </button>

        <button class="ui button merge-cancel" type="button" @click="bypassRequested = false; toggleActionForm(false)">
          {{ mergeForm.textCancel }}
        </button>

        <div class="ui checkbox" v-if="mergeForm.isPullBranchDeletable">
          <input name="delete_branch_after_merge" type="checkbox" v-model="deleteBranchAfterMerge" id="delete-branch-after-merge">
          <label for="delete-branch-after-merge">{{ mergeForm.textDeleteBranch }}</label>
        </div>
      </div>
    </form>

    <div v-if="!showActionForm" class="flex-text-block tw-gap-3">
      <!-- the merge button -->
      <div class="ui buttons merge-button" :class="mergeSelectStyleClass" @click="toggleActionForm(true)">
        <button type="button" class="ui button" :disabled="!gateSubmitAllowed && mergeStyle !== mergeStyleManuallyMerged">
          <svg-icon name="octicon-git-merge"/>
          <span class="button-text">
            {{ mergeStyleDetail.textDoMerge }}
            <template v-if="autoMergeWhenSucceed">
              {{ mergeForm.textAutoMergeButtonWhenSucceed }}
            </template>
          </span>
        </button>
        <div class="ui dropdown icon button">
          <button type="button" class="btn" :aria-label="mergeStyleDetail.textDoMerge" :aria-expanded="showMergeStyleMenu" @click.stop="showMergeStyleMenu = !showMergeStyleMenu">
            <svg-icon name="octicon-triangle-down" :size="14"/>
          </button>
          <div class="menu" :class="{'show':showMergeStyleMenu}">
            <template v-for="msd in mergeForm.mergeStyles">
              <!-- if can merge now, show one action "merge now", and an action "auto merge when succeed" -->
              <div class="item" v-if="msd.allowed && mergeForm.canMergeNow" :key="msd.name">
                <button type="button" class="btn action-text" @click.stop="switchMergeStyle(msd.name)">
                  {{ msd.textDoMerge }}
                </button>
                <button type="button" v-if="!msd.hideAutoMerge" class="btn auto-merge-small" :aria-label="mergeForm.textAutoMergeWhenSucceed" @click.stop="switchMergeStyle(msd.name, true)">
                  <svg-icon name="octicon-clock" :size="14"/>
                  <div class="auto-merge-tip">
                    {{ mergeForm.textAutoMergeWhenSucceed }}
                  </div>
                </button>
              </div>

              <!-- if can NOT merge now, only show one action "auto merge when succeed" -->
              <button type="button" class="btn item" v-if="msd.allowed && !mergeForm.canMergeNow && !msd.hideAutoMerge" :key="msd.name" @click.stop="switchMergeStyle(msd.name, true)">
                <div class="action-text">
                  {{ msd.textDoMerge }} {{ mergeForm.textAutoMergeButtonWhenSucceed }}
                </div>
              </button>
            </template>
          </div>
        </div>
      </div>

      <button v-if="gateBypassAvailable" data-merge-gate-bypass type="button" class="ui red button" @click="toggleActionForm(true); bypassRequested = true">
        {{ mergeForm.mergeGate!.textBypass }}
      </button>
      <!-- the cancel auto merge button -->
      <form v-if="mergeForm.hasPendingPullRequestMerge" :action="mergeForm.baseLink+'/cancel_auto_merge'" method="post" class="form-fetch-action">
        <button class="ui button">
          {{ mergeForm.textAutoMergeCancelSchedule }}
        </button>
      </form>
    </div>
  </div>
</template>

<style scoped>
/* to keep UI the same, at the moment we are still using some Fomantic UI styles, but we do not use their scripts, so we need to fine tune some styles */
.ui.dropdown .menu.show {
  display: block;
}
.ui.checkbox label {
  cursor: pointer;
}

/* make the dropdown list left-aligned */
.ui.merge-button {
  position: relative;
}
.ui.merge-button .ui.dropdown {
  position: static;
}
.ui.merge-button > .ui.dropdown:last-child > .menu:not(.left) {
  left: 0;
  right: auto;
}
.ui.merge-button .ui.dropdown .menu > .item {
  display: flex;
  align-items: stretch;
  padding: 0 !important; /* polluted by semantic.css: .ui.dropdown .menu > .item { !important } */
}

/* merge style list item */
.action-text {
  padding: 0.8rem;
  flex: 1
}

.auto-merge-small {
  width: 40px;
  display: flex;
  align-items: center;
  justify-content: center;
  position: relative;
}
.auto-merge-small .auto-merge-tip {
  display: none;
  left: 38px;
  top: -1px;
  bottom: -1px;
  position: absolute;
  align-items: center;
  color: var(--color-text);
  background-color: var(--color-info-bg);
  border: 1px solid var(--color-info-border);
  border-left: none;
  padding-right: 1rem;
}

.auto-merge-small:hover {
  color: var(--color-text);
  background-color: var(--color-info-bg);
  border: 1px solid var(--color-info-border);
}

.auto-merge-small:hover .auto-merge-tip {
  display: flex;
}

</style>
