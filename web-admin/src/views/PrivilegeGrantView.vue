<template>
  <div class="page">
    <section class="grant-hero glass">
      <div class="grant-hero__copy">
        <span class="grant-eyebrow">
          <span class="grant-eyebrow__dot" aria-hidden="true"></span>
          {{ $t('privilegeGrant.eyebrow') }}
        </span>
        <h1 class="grant-hero__title">{{ $t('privilegeGrant.pageTitle') }}</h1>
        <p class="grant-hero__subtitle">{{ $t('privilegeGrant.pageSubtitle') }}</p>
        <div class="rule-chips" role="list">
          <span class="rule-chip" role="listitem">
            <el-icon><Timer /></el-icon>{{ $t('privilegeGrant.ruleDuration') }}
          </span>
          <span class="rule-chip" role="listitem">
            <el-icon><Lock /></el-icon>{{ $t('privilegeGrant.ruleDual') }}
          </span>
          <span class="rule-chip" role="listitem">
            <el-icon><Clock /></el-icon>{{ $t('privilegeGrant.ruleExpire') }}
          </span>
        </div>
      </div>
      <div class="grant-hero__actions">
        <button
          v-if="canGrant"
          type="button"
          class="glass-btn glass-btn--primary grant-cta"
          @click="toggleCreate"
        >
          <el-icon><Plus /></el-icon>
          {{ creating ? $t('common.cancel') : $t('privilegeGrant.request') }}
        </button>
      </div>
    </section>

    <el-alert
      v-if="loadError"
      :title="rows.length > 0 ? $t('privilegeGrant.staleData') : $t('privilegeGrant.loadError')"
      type="warning"
      :closable="false"
      show-icon
      class="load-error"
    >
      <template #default>
        <button
          type="button"
          class="glass-btn glass-btn--default glass-btn--sm"
          :disabled="loading"
          @click="loadAll"
        >
          {{ $t('common.retry') }}
        </button>
      </template>
    </el-alert>

    <div v-if="summary || summaryFailed" class="summary-grid" aria-live="polite">
      <button
        v-for="card in summaryCards"
        :key="card.key"
        type="button"
        class="summary-card"
        :class="summaryCardClass(card)"
        @click="handleSummaryCard(card)"
      >
        <span class="summary-card__top">
          <span class="summary-value">{{ card.value }}</span>
          <el-icon class="summary-card__icon"><component :is="card.icon" /></el-icon>
        </span>
        <span class="summary-label">{{ card.label }}</span>
        <span class="summary-hint">{{ card.hint }}</span>
      </button>
    </div>

    <div v-if="summaryFailed" class="summary-failed" role="status">
      <el-icon><Warning /></el-icon>
      <span class="summary-failed__text">{{ $t('privilegeGrant.summaryLoadFailed') }}</span>
      <button
        type="button"
        class="glass-btn glass-btn--default glass-btn--sm"
        :disabled="loading"
        @click="loadSummary"
      >
        {{ $t('common.retry') }}
      </button>
    </div>

    <section v-if="creating" class="create-form" :aria-label="$t('privilegeGrant.requestTitle')">
      <header class="create-form__header">
        <div>
          <h2 class="create-form__title">{{ $t('privilegeGrant.requestTitle') }}</h2>
          <p class="create-form__subtitle">{{ $t('privilegeGrant.requestSubtitle') }}</p>
        </div>
        <button
          type="button"
          class="icon-btn"
          :aria-label="$t('common.cancel')"
          @click="toggleCreate"
        >
          <el-icon><Close /></el-icon>
        </button>
      </header>

      <div class="request-layout">
        <div class="request-main">
          <section class="form-section">
            <div class="form-section__head">
              <span class="step-number">1</span>
              <div>
                <h3>{{ $t('privilegeGrant.stepUser') }}</h3>
                <p>{{ $t('privilegeGrant.stepUserHint') }}</p>
              </div>
            </div>

            <el-select
              v-if="showUserSelect"
              v-model="createForm.targetUserId"
              filterable
              remote
              clearable
              :remote-method="loadUserOptions"
              :loading="usersState === 'loading' || userSearching"
              :placeholder="$t('privilegeGrant.userSearchPlaceholder')"
              class="form-control form-control--full"
              :no-data-text="
                userSearchFailed
                  ? $t('privilegeGrant.userLoadFailed')
                  : $t('privilegeGrant.noUserFound')
              "
            >
              <el-option
                v-for="user in userSelectOptions"
                :key="user._id"
                :label="userLabel(user)"
                :value="user._id"
              >
                <div class="user-option">
                  <span class="user-option__avatar" aria-hidden="true">{{ initials(user) }}</span>
                  <span class="user-option__main">
                    <strong>{{ user.username }}</strong>
                    <small>{{
                      [user.realName, user.department].filter(Boolean).join(' · ') || '-'
                    }}</small>
                  </span>
                  <el-tag v-if="user.status && user.status !== 'active'" size="small" type="info">
                    {{ user.status }}
                  </el-tag>
                </div>
              </el-option>
            </el-select>
            <el-input
              v-else
              v-model="createForm.targetUserId"
              data-testid="target-user-input"
              maxlength="32"
              :placeholder="$t('privilegeGrant.targetUserPlaceholder')"
              class="form-control form-control--full"
            />

            <div class="field-help">
              <span v-if="selectedUser" class="selected-user">
                <span class="selected-user__dot" aria-hidden="true"></span>
                {{ $t('privilegeGrant.selectedUser') }}：{{ userLabel(selectedUser) }}
              </span>
              <span v-else-if="usersState === 'loading'" class="field-help__muted">
                {{ $t('privilegeGrant.userLoading') }}
              </span>
              <span
                v-else-if="usersState === 'unavailable' || userSearchFailed"
                class="field-help__muted"
              >
                {{ $t('privilegeGrant.userLoadFailed') }}
              </span>
              <button
                v-if="usersState === 'ready'"
                type="button"
                class="text-link"
                @click="manualUser = !manualUser"
              >
                {{
                  manualUser ? $t('privilegeGrant.useUserPicker') : $t('privilegeGrant.manualUser')
                }}
              </button>
            </div>
          </section>

          <section class="form-section">
            <div class="form-section__head">
              <span class="step-number">2</span>
              <div>
                <h3>{{ $t('privilegeGrant.stepPermissions') }}</h3>
                <p>{{ $t('privilegeGrant.stepPermissionsHint') }}</p>
              </div>
            </div>

            <template v-if="showPermissionPicker">
              <div class="permission-toolbar">
                <el-input
                  v-model="permSearch"
                  :placeholder="$t('privilegeGrant.permissionSearchPlaceholder')"
                  clearable
                  class="permission-search"
                >
                  <template #prefix
                    ><el-icon><Search /></el-icon
                  ></template>
                </el-input>
                <span class="permission-count">
                  {{
                    $t('privilegeGrant.selectedCount', { count: selectedPermissionCodes.length })
                  }}
                </span>
                <button
                  type="button"
                  class="text-link permission-toolbar__manual"
                  @click="manualCodesMode = true"
                >
                  {{ $t('privilegeGrant.manualCodes') }}
                </button>
              </div>

              <div v-if="filteredPermissionGroups.length === 0" class="permission-empty">
                {{ $t('privilegeGrant.noPermissionFound') }}
              </div>
              <div v-else class="permission-groups">
                <div
                  v-for="group in filteredPermissionGroups"
                  :key="group.module"
                  class="permission-group"
                >
                  <div class="permission-group__head">
                    <span class="permission-group__icon" aria-hidden="true">{{ group.icon }}</span>
                    <span class="permission-group__name">{{ moduleName(group) }}</span>
                    <button
                      type="button"
                      class="text-link permission-group__toggle"
                      @click="togglePermissionGroup(group)"
                    >
                      {{
                        isGroupFullySelected(group)
                          ? $t('privilegeGrant.clearModule')
                          : $t('privilegeGrant.selectAllModule')
                      }}
                    </button>
                  </div>
                  <div class="permission-options">
                    <label
                      v-for="perm in group.permissions"
                      :key="perm.code"
                      class="permission-option"
                      :class="permissionOptionClass(perm)"
                    >
                      <input
                        class="permission-option__input"
                        type="checkbox"
                        :value="perm.code"
                        :checked="isCodeSelected(perm.code)"
                        @change="togglePermissionCode(perm.code)"
                      />
                      <span class="permission-option__check" aria-hidden="true">
                        {{ isCodeSelected(perm.code) ? '✓' : '' }}
                      </span>
                      <span class="permission-option__body">
                        <span class="permission-option__name">{{
                          permissionDisplayName(perm.code)
                        }}</span>
                        <code class="permission-option__code">{{ perm.code }}</code>
                      </span>
                      <span v-if="isHighRiskCode(perm.code)" class="permission-option__risk">
                        {{ $t('privilegeGrant.highRiskShort') }}
                      </span>
                    </label>
                  </div>
                </div>
              </div>

              <div v-if="selectedPermissionCodes.length > 0" class="selected-codes">
                <span v-for="code in selectedPermissionCodes" :key="code" class="selected-code">
                  {{ code }}
                  <button
                    type="button"
                    class="selected-code__remove"
                    :aria-label="$t('common.delete')"
                    @click="togglePermissionCode(code)"
                  >
                    ×
                  </button>
                </span>
              </div>
            </template>

            <template v-else>
              <el-input
                v-model="manualCodesText"
                data-testid="manual-codes-input"
                :placeholder="$t('privilegeGrant.codesHint')"
                maxlength="400"
                class="form-control form-control--full"
              />
              <div class="field-help">
                <span class="field-help__muted">{{
                  manualCodesMode && permissionState === 'ready'
                    ? $t('privilegeGrant.codesHint')
                    : $t('privilegeGrant.permissionLoadFailed')
                }}</span>
                <button
                  v-if="manualCodesMode && permissionState === 'ready'"
                  type="button"
                  class="text-link"
                  @click="manualCodesMode = false"
                >
                  {{ $t('privilegeGrant.usePermissionPicker') }}
                </button>
              </div>
            </template>
          </section>

          <section class="form-section">
            <div class="form-section__head">
              <span class="step-number">3</span>
              <div>
                <h3>{{ $t('privilegeGrant.stepDuration') }}</h3>
                <p>{{ $t('privilegeGrant.durationHint') }}</p>
              </div>
            </div>

            <div
              class="duration-presets"
              role="group"
              :aria-label="$t('privilegeGrant.stepDuration')"
            >
              <button
                v-for="preset in durationPresets"
                :key="preset.hours"
                type="button"
                class="duration-preset"
                :class="{ 'is-active': Number(createForm.durationHours) === preset.hours }"
                @click="setDuration(preset.hours)"
              >
                {{ preset.label }}
              </button>
            </div>
            <div class="duration-custom">
              <el-input
                v-model="createForm.durationHours"
                data-testid="duration-input"
                type="number"
                :min="MIN_GRANT_HOURS"
                :max="MAX_GRANT_HOURS"
                class="form-control form-control--narrow"
              >
                <template #append>{{ $t('privilegeGrant.hoursUnit') }}</template>
              </el-input>
              <span class="duration-custom__hint">
                {{
                  $t('privilegeGrant.durationCustom', {
                    min: MIN_GRANT_HOURS,
                    max: MAX_GRANT_HOURS,
                  })
                }}
              </span>
            </div>
            <div v-if="durationOutOfRange" class="expiry-preview">
              <el-icon><Warning /></el-icon>
              <span>
                {{
                  $t('privilegeGrant.durationInvalid', {
                    min: MIN_GRANT_HOURS,
                    max: MAX_GRANT_HOURS,
                  })
                }}
              </span>
            </div>
            <div v-if="estimatedExpiry" class="expiry-preview">
              <el-icon><Clock /></el-icon>
              <span>
                {{ $t('privilegeGrant.expirePreview', { time: estimatedExpiry }) }}
                <small>{{ $t('privilegeGrant.expirePreviewHint') }}</small>
              </span>
            </div>
          </section>

          <section class="form-section">
            <div class="form-section__head">
              <span class="step-number">4</span>
              <div>
                <h3>{{ $t('privilegeGrant.stepReason') }}</h3>
                <p>{{ $t('privilegeGrant.reasonHint') }}</p>
              </div>
            </div>
            <el-input
              v-model="createForm.reason"
              data-testid="reason-input"
              type="textarea"
              :rows="3"
              maxlength="200"
              show-word-limit
              :placeholder="$t('privilegeGrant.reasonPlaceholder')"
              class="form-control form-control--full"
            />
          </section>
        </div>

        <aside class="request-preview">
          <div class="request-preview__head">
            <span class="request-preview__eyebrow">{{ $t('privilegeGrant.previewTitle') }}</span>
            <span class="request-preview__hint">{{ $t('privilegeGrant.previewHint') }}</span>
          </div>
          <dl class="preview-list">
            <div class="preview-row">
              <dt>{{ $t('privilegeGrant.targetUser') }}</dt>
              <dd>{{ selectedTargetLabel || $t('privilegeGrant.notSelected') }}</dd>
            </div>
            <div class="preview-row">
              <dt>{{ $t('privilegeGrant.codes') }}</dt>
              <dd>{{ $t('privilegeGrant.selectedCount', { count: effectiveCodes.length }) }}</dd>
            </div>
            <div class="preview-row">
              <dt>{{ $t('privilegeGrant.duration') }}</dt>
              <dd>{{ durationText(Number(createForm.durationHours)) }}</dd>
            </div>
            <div class="preview-row">
              <dt>{{ $t('privilegeGrant.approvalRequired') }}</dt>
              <dd :class="{ 'is-warning': approvalPolicy.highRisk }">
                {{
                  $t('privilegeGrant.approvalPeople', { count: approvalPolicy.requiredApprovals })
                }}
              </dd>
            </div>
          </dl>
          <div v-if="effectiveCodes.length > 0" class="preview-codes">
            <span v-for="code in effectiveCodes.slice(0, 8)" :key="code" class="preview-code">{{
              code
            }}</span>
            <span v-if="effectiveCodes.length > 8" class="preview-more"
              >+{{ effectiveCodes.length - 8 }}</span
            >
          </div>
          <div v-if="approvalPolicy.highRisk" class="preview-warning">
            <el-icon><Warning /></el-icon>
            <span>{{ $t('privilegeGrant.highRiskHint') }}</span>
          </div>
          <div v-if="reservedSelection" class="preview-warning">
            <el-icon><Warning /></el-icon>
            <span>{{ $t('privilegeGrant.reservedCodeBlocked', { code: reservedSelection }) }}</span>
          </div>
          <div v-if="isSelfTarget" class="preview-note">
            <el-icon><Warning /></el-icon>
            <span>{{ $t('privilegeGrant.selfTargetHint') }}</span>
          </div>
          <div class="preview-note">
            <el-icon><Lock /></el-icon>
            <span>{{ $t('privilegeGrant.previewNote') }}</span>
          </div>
        </aside>
      </div>

      <footer class="create-form__footer">
        <span class="submit-hint">{{ submitHint }}</span>
        <div class="glass-btn-group">
          <button
            type="button"
            class="glass-btn glass-btn--default"
            :disabled="submitting"
            @click="toggleCreate"
          >
            {{ $t('common.cancel') }}
          </button>
          <button
            type="button"
            class="glass-btn glass-btn--primary"
            :disabled="submitting"
            @click="handleCreate"
          >
            {{ submitting ? $t('common.submitting') : $t('privilegeGrant.submitRequest') }}
          </button>
        </div>
      </footer>
    </section>

    <div class="glass glass-card table-card">
      <div class="table-toolbar">
        <div class="toolbar-left">
          <GlassSegmented
            v-model="statusFilter"
            :options="statusOptions"
            :aria-label="$t('privilegeGrant.statusFilterLabel')"
            @change="handleStatusChange"
          />
        </div>
        <div class="glass-btn-group">
          <button
            type="button"
            class="glass-btn glass-btn--default"
            :disabled="loading"
            @click="loadAll"
          >
            <el-icon><Refresh /></el-icon>{{ $t('common.refresh') }}
          </button>
        </div>
      </div>

      <el-table
        v-loading="loading"
        :data="rows"
        :row-class-name="rowClassName"
        border
        stripe
        style="width: 100%"
      >
        <template #empty>
          <div v-if="!loading" class="empty-state">
            <div class="empty-state__icon" aria-hidden="true">⌛</div>
            <div class="empty-tip">{{ emptyTitle }}</div>
            <p class="empty-state__hint">{{ emptyHint }}</p>
            <button
              v-if="canGrant"
              type="button"
              class="glass-btn glass-btn--primary glass-btn--sm"
              @click="toggleCreate"
            >
              {{ $t('privilegeGrant.emptyCta') }}
            </button>
          </div>
        </template>

        <el-table-column :label="$t('privilegeGrant.colUser')" min-width="160">
          <template #default="{ row }">
            <span class="user-cell">
              <span class="user-cell__avatar" aria-hidden="true">{{ initials(row) }}</span>
              <span class="user-cell__name">{{ row.username || row.userId }}</span>
            </span>
          </template>
        </el-table-column>
        <el-table-column :label="$t('privilegeGrant.colCodes')" min-width="240">
          <template #default="{ row }">
            <el-tag
              v-for="code in visibleCodes(row)"
              :key="code"
              size="small"
              effect="plain"
              class="code-tag"
              :title="permissionDisplayName(code)"
            >
              {{ permissionDisplayName(code) }}
            </el-tag>
            <el-tag
              v-if="(row.permissionCodes || []).length > 2"
              size="small"
              type="info"
              class="code-tag"
            >
              +{{ (row.permissionCodes || []).length - 2 }}
            </el-tag>
            <el-tag v-if="row.highRisk" type="warning" size="small" class="code-tag">
              {{ $t('privilegeGrant.highRisk') }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column :label="$t('privilegeGrant.colApprovals')" width="134">
          <template #default="{ row }">
            <div class="approval-cell" :title="approvalTitle(row)">
              <span class="approval-count"
                >{{ approvalCount(row) }}/{{ requiredApprovals(row) }}</span
              >
              <span class="approval-dots" aria-hidden="true">
                <i
                  v-for="index in requiredApprovals(row)"
                  :key="index"
                  :class="{ 'is-filled': index <= approvalCount(row) }"
                ></i>
              </span>
            </div>
          </template>
        </el-table-column>
        <el-table-column :label="$t('privilegeGrant.colStatus')" width="112">
          <template #default="{ row }">
            <el-tag :type="statusTagType(displayStatus(row))" size="small">{{
              statusLabel(displayStatus(row))
            }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column :label="$t('privilegeGrant.colRequestedAt')" width="166">
          <template #default="{ row }">{{ formatTime(row.requestedAt) }}</template>
        </el-table-column>
        <el-table-column :label="$t('privilegeGrant.colExpiresAt')" width="176">
          <template #default="{ row }">
            <div class="expiry-cell">
              <span>{{ formatTime(row.expiresAt) }}</span>
              <small
                v-if="row.expiresAt && displayStatus(row) === 'active'"
                class="expiry-remaining"
              >
                {{ remainingLabel(row) }}
              </small>
            </div>
          </template>
        </el-table-column>
        <el-table-column :label="$t('common.operation')" width="224" fixed="right">
          <template #default="{ row }">
            <div class="glass-btn-group glass-btn-group--tight action-group">
              <button
                type="button"
                class="glass-btn glass-btn--default glass-btn--link"
                @click="openDetails(row)"
              >
                {{ $t('privilegeGrant.details') }}
              </button>
              <template v-if="row.status === 'pending' && canApprove">
                <button
                  v-if="canDecideRow(row)"
                  type="button"
                  class="glass-btn glass-btn--success glass-btn--link"
                  :disabled="decidingId !== null"
                  @click="handleApprove(row)"
                >
                  {{ $t('privilegeGrant.approve') }}
                </button>
                <button
                  v-if="canDecideRow(row)"
                  type="button"
                  class="glass-btn glass-btn--warning glass-btn--link"
                  :disabled="decidingId !== null"
                  @click="handleReject(row)"
                >
                  {{ $t('privilegeGrant.reject') }}
                </button>
                <span v-else class="action-hint" :title="actionHint(row)">{{
                  actionHint(row)
                }}</span>
              </template>
              <button
                v-if="row.status === 'pending' && canGrant && isRequesterRow(row)"
                type="button"
                class="glass-btn glass-btn--default glass-btn--link"
                :disabled="decidingId !== null"
                @click="handleWithdraw(row)"
              >
                {{ $t('privilegeGrant.withdraw') }}
              </button>
              <button
                v-if="row.status === 'active' && canGrant"
                type="button"
                class="glass-btn glass-btn--danger glass-btn--link"
                :disabled="decidingId !== null"
                @click="handleRevoke(row)"
              >
                {{ $t('privilegeGrant.revoke') }}
              </button>
            </div>
          </template>
        </el-table-column>
      </el-table>

      <div class="pagination">
        <el-pagination
          v-model:current-page="page.current"
          v-model:page-size="page.size"
          :total="page.total"
          :page-sizes="[20, 50, 100]"
          layout="total, sizes, prev, pager, next, jumper"
          background
          @current-change="loadData"
          @size-change="handleSizeChange"
        />
      </div>
    </div>

    <el-drawer
      v-model="detailVisible"
      :with-header="false"
      size="520px"
      append-to-body
      class="grant-detail-drawer"
    >
      <div v-if="detailGrant" class="detail-drawer">
        <header class="detail-drawer__header">
          <div>
            <span class="detail-drawer__eyebrow">{{ $t('privilegeGrant.detailsTitle') }}</span>
            <h2>{{ detailGrant.username || detailGrant.userId }}</h2>
          </div>
          <button
            type="button"
            class="icon-btn"
            :aria-label="$t('common.cancel')"
            @click="detailVisible = false"
          >
            <el-icon><Close /></el-icon>
          </button>
        </header>

        <div class="detail-status">
          <el-tag :type="statusTagType(detailStatus)" size="small">{{
            statusLabel(detailStatus)
          }}</el-tag>
          <el-tag v-if="detailGrant.highRisk" type="warning" size="small">{{
            $t('privilegeGrant.highRisk')
          }}</el-tag>
          <span v-if="detailStatus === 'active'" class="detail-status__remaining">
            {{ remainingLabel(detailGrant) }}
          </span>
        </div>

        <section class="detail-section">
          <h3>{{ $t('privilegeGrant.targetUser') }}</h3>
          <p class="detail-primary">{{ detailGrant.username || detailGrant.userId }}</p>
          <p class="detail-muted">{{ $t('privilegeGrant.userId') }}：{{ detailGrant.userId }}</p>
          <p class="detail-muted">
            {{ $t('privilegeGrant.requester') }}：{{ detailGrant.requestedByName || '-' }} ·
            {{ formatTime(detailGrant.requestedAt) }}
          </p>
        </section>

        <section class="detail-section">
          <h3>{{ $t('privilegeGrant.codes') }}</h3>
          <div class="detail-codes">
            <el-tag
              v-for="code in detailGrant.permissionCodes || []"
              :key="code"
              size="small"
              effect="plain"
              :title="code"
            >
              {{ permissionDisplayName(code) }}
            </el-tag>
          </div>
        </section>

        <section class="detail-section">
          <h3>{{ $t('privilegeGrant.reasonLabel') }}</h3>
          <p class="detail-reason">{{ detailGrant.reason || '-' }}</p>
        </section>

        <section class="detail-section">
          <h3>{{ $t('privilegeGrant.approvalTrail') }}</h3>
          <ol class="timeline">
            <li
              v-for="item in detailTimeline"
              :key="item.key"
              class="timeline__item"
              :class="'is-' + item.tone"
            >
              <span class="timeline__dot" aria-hidden="true"></span>
              <div class="timeline__body">
                <span class="timeline__title">{{ item.title }}</span>
                <span v-if="item.time" class="timeline__time">{{ formatTime(item.time) }}</span>
                <span v-if="item.detail" class="timeline__detail">{{ item.detail }}</span>
              </div>
            </li>
          </ol>
        </section>

        <section class="detail-section detail-section--grid">
          <div>
            <h3>{{ $t('privilegeGrant.duration') }}</h3>
            <p class="detail-primary">{{ durationText(detailGrant.durationHours) }}</p>
          </div>
          <div>
            <h3>{{ $t('privilegeGrant.colExpiresAt') }}</h3>
            <p class="detail-primary">{{ formatTime(detailGrant.expiresAt) }}</p>
          </div>
        </section>

        <section v-if="detailGrant.decisionReason" class="detail-section">
          <h3>{{ $t('privilegeGrant.decisionReason') }}</h3>
          <p class="detail-reason">{{ detailGrant.decisionReason }}</p>
        </section>

        <!-- 撤销说明与「处理说明」是两条不同的留痕：撤销不覆写 decided*（见后端
             privilegeGrantService 的 revocationFields 注释），所以撤销后「谁批的」
             和「为什么撤」必须分别可读。只在撤销态且确有说明时渲染，避免空段。 -->
        <section
          v-if="detailStatus === 'revoked' && detailGrant.revokeReason"
          class="detail-section"
        >
          <h3>{{ $t('privilegeGrant.revokeReason') }}</h3>
          <p class="detail-reason">{{ detailGrant.revokeReason }}</p>
        </section>
      </div>
    </el-drawer>

    <el-dialog
      v-model="overdueVisible"
      :title="$t('privilegeGrant.overdueDrawerTitle')"
      width="640px"
      append-to-body
    >
      <p class="overdue-dialog__hint">{{ $t('privilegeGrant.overdueHint') }}</p>
      <p v-if="summary && summary.overdue > overdueGrants.length" class="overdue-dialog__hint">
        {{
          $t('privilegeGrant.overdueMore', {
            shown: overdueGrants.length,
            total: summary.overdue,
          })
        }}
      </p>
      <div v-if="overdueGrants.length === 0" class="overdue-empty">
        {{ $t('privilegeGrant.overdueEmpty') }}
      </div>
      <div v-else class="overdue-list">
        <button
          v-for="grant in overdueGrants"
          :key="grant._id"
          type="button"
          class="overdue-item"
          @click="openOverdueDetails(grant)"
        >
          <span class="overdue-item__user">{{ grant.username || grant.userId }}</span>
          <span class="overdue-item__meta">
            {{ $t('privilegeGrant.overdueDays', { count: daysSince(grant.grantedAt) }) }}
            · {{ (grant.permissionCodes || []).length }} {{ $t('privilegeGrant.items') }}
          </span>
          <el-icon><ArrowRight /></el-icon>
        </button>
      </div>
      <template #footer>
        <button type="button" class="glass-btn glass-btn--default" @click="overdueVisible = false">
          {{ $t('common.close') }}
        </button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, nextTick, onMounted, onUnmounted, reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'
import { ElMessageBox } from 'element-plus/es/components/message-box/index.mjs'
import {
  ArrowRight,
  Clock,
  Close,
  Lock,
  Plus,
  Refresh,
  Search,
  Timer,
  Warning,
} from '@element-plus/icons-vue'
import { api, isCanceledError, isHandledApiError } from '@/utils/api'
import { createSubmissionKey } from '@/utils/idempotency'
import { formatTime } from '@/utils/datetime'
import { usePermission } from '@/composables/usePermission'
import { useLatestRequest } from '@/composables/useLatestRequest'
import { useAuthStore } from '@/store'
import { useSystemLabels } from '@/i18n/systemLabels'
import GlassSegmented from '@/components/GlassSegmented.vue'
import {
  MAX_GRANT_CODES,
  MAX_GRANT_HOURS,
  MIN_GRANT_HOURS,
  approvalPolicyOf,
  effectiveStatusOf,
  isHighRiskCode,
  isReservedCode,
  parsePermissionCodes,
  remainingOf,
} from '@/utils/privilegeGrant'

const { t } = useI18n()
const { hasPerm } = usePermission()
const { permissionName } = useSystemLabels()
const authStore = useAuthStore()
const listGuard = useLatestRequest()

const canGrant = computed(() => hasPerm('privilege:grant'))
const canApprove = computed(() => hasPerm('privilege:approve'))

const loading = ref(false)
const loadError = ref(false)
const rows = ref([])
const summary = ref(null)
// 复核汇总失败：与「待审批 0 条 / 超期 0 条」是两件事。前者必须给「—」+ 明确提示，
// 后者才能给 0——把「没读到」画成 0 会让复核人以为没有待办，正好漏掉该处理的授权。
const summaryFailed = ref(false)
const page = reactive({ current: 1, size: 20, total: 0 })

// 有签批权限的人打开页面先看待办；只读/申请人直接看全部，避免落在永远空的「待审批」
const statusFilter = ref(canApprove.value ? 'pending' : '')

const creating = ref(false)
const submitting = ref(false)
// 本次授权的幂等键（审计一-1）：重复提交会产出两条待审记录
const submission = createSubmissionKey()
const decidingId = ref(null)
const createForm = reactive({
  targetUserId: '',
  permissionCodes: [],
  durationHours: 8,
  reason: '',
})
const manualUser = ref(false)
const manualCodesText = ref('')
const manualCodesMode = ref(false)
const permSearch = ref('')

const usersState = ref('idle')
const userOptions = ref([])
// 用户候选项走服务端搜索：生产环境用户数远超单页上限，一次性拉全量既慢又搜不到人
const USER_SEARCH_LIMIT = 50
const userSearching = ref(false)
const userSearchFailed = ref(false)
const userSearchGuard = useLatestRequest()
// 已选用户的对象副本：远程搜索会整表替换候选项，没有它「已选：xxx」会退回裸 _id
const userCache = ref(new Map())
const permissionState = ref('idle')
const permissionGroups = ref([])
const permissionMap = ref(new Map())

const detailVisible = ref(false)
const detailGrant = ref(null)

// 剩余时间/生效态要跟着钟走：到期回收由独立进程的巡检脚本执行，
// 它停摆时库里的 active 记录实际已失效，界面不能比读侧判据更乐观
const nowTick = ref(Date.now())
let tickTimer = null
const overdueVisible = ref(false)

const statusOptions = computed(() => [
  {
    value: 'pending',
    label: t('privilegeGrant.statusPending'),
    // 汇总没读到时不给数字（GlassSegmented 对 undefined 不渲染计数），绝不显示 0
    count: summaryFailed.value ? undefined : summary.value?.pending,
  },
  {
    value: 'active',
    label: t('privilegeGrant.statusActive'),
    count: summaryFailed.value ? undefined : summary.value?.active,
  },
  { value: 'expired', label: t('privilegeGrant.statusExpired') },
  { value: 'revoked', label: t('privilegeGrant.statusRevoked') },
  { value: 'rejected', label: t('privilegeGrant.statusRejected') },
  { value: '', label: t('privilegeGrant.statusAll') },
])

// 卡片取值：失败态一律 '—'（未知），成功态才给数字；?? 保证真实的 0 仍然是 0
const summaryCardValue = (key) => (summaryFailed.value ? '—' : (summary.value?.[key] ?? 0))

const summaryCards = computed(() => [
  {
    key: 'pending',
    value: summaryCardValue('pending'),
    label: t('privilegeGrant.sumPending'),
    hint: t('privilegeGrant.sumPendingHint'),
    tone: 'warning',
    icon: Timer,
    active: statusFilter.value === 'pending',
    targetStatus: 'pending',
  },
  {
    key: 'active',
    value: summaryCardValue('active'),
    label: t('privilegeGrant.sumActive'),
    hint: t('privilegeGrant.sumActiveHint'),
    tone: 'success',
    icon: Clock,
    active: statusFilter.value === 'active',
    targetStatus: 'active',
  },
  {
    key: 'expiringSoon',
    value: summaryCardValue('expiringSoon'),
    label: t('privilegeGrant.sumExpiringSoon'),
    hint: t('privilegeGrant.sumExpiringHint'),
    tone: 'warning',
    icon: Clock,
    active: false,
    targetStatus: 'active',
  },
  {
    key: 'highRiskActive',
    value: summaryCardValue('highRiskActive'),
    label: t('privilegeGrant.sumHighRisk'),
    hint: t('privilegeGrant.sumHighRiskHint'),
    tone: 'danger',
    icon: Lock,
    active: false,
    targetStatus: 'active',
  },
  {
    key: 'overdue',
    value: summaryCardValue('overdue'),
    label: t('privilegeGrant.sumOverdue'),
    hint: t('privilegeGrant.sumOverdueHint'),
    tone: 'info',
    icon: Warning,
    active: false,
    targetStatus: '',
  },
])

const STATUS_LABEL_KEYS = {
  pending: 'privilegeGrant.statusPending',
  active: 'privilegeGrant.statusActive',
  expired: 'privilegeGrant.statusExpired',
  revoked: 'privilegeGrant.statusRevoked',
  rejected: 'privilegeGrant.statusRejected',
}
const STATUS_TAG_TYPES = {
  pending: 'warning',
  active: 'success',
  expired: 'info',
  revoked: 'info',
  rejected: 'danger',
}
const statusLabel = (status) => t(STATUS_LABEL_KEYS[status] || 'privilegeGrant.statusUnknown')
const statusTagType = (status) => STATUS_TAG_TYPES[status] || 'info'

const durationPresets = computed(() => [
  { hours: 1, label: t('privilegeGrant.preset1') },
  { hours: 8, label: t('privilegeGrant.preset8') },
  { hours: 24, label: t('privilegeGrant.preset24') },
  { hours: 72, label: t('privilegeGrant.preset72') },
  { hours: 168, label: t('privilegeGrant.preset168') },
])

const durationText = (hours) => {
  const value = Number(hours)
  if (!Number.isFinite(value) || value <= 0) return '-'
  if (value % 24 === 0) return t('privilegeGrant.days', { count: value / 24 })
  return t('privilegeGrant.hours', { count: value })
}

const selectedUser = computed(() => {
  const id = String(createForm.targetUserId || '')
  if (!id) return null
  return (
    userCache.value.get(id) || userOptions.value.find((user) => String(user._id) === id) || null
  )
})
// 已选中的用户必须始终留在候选项里：远程搜索换页后 EP 找不到该项会退回裸 _id 当标签
const userSelectOptions = computed(() => {
  const picked = selectedUser.value
  if (!picked) return userOptions.value
  if (userOptions.value.some((user) => String(user._id) === String(picked._id)))
    return userOptions.value
  return [picked, ...userOptions.value]
})
const selectedTargetLabel = computed(() =>
  selectedUser.value ? userLabel(selectedUser.value) : String(createForm.targetUserId || '').trim()
)
// 选择器可用性只看能力状态：搜索零结果时不能把控件换成手填输入框（用户正在打字）
const showUserSelect = computed(() => usersState.value === 'ready' && !manualUser.value)

const selectedPermissionCodes = computed(() => createForm.permissionCodes)
const showPermissionPicker = computed(
  () =>
    permissionState.value === 'ready' && permissionGroups.value.length > 0 && !manualCodesMode.value
)
const effectiveCodes = computed(() => {
  if (showPermissionPicker.value) return selectedPermissionCodes.value
  return parsePermissionCodes(manualCodesText.value)
})
const reservedSelection = computed(
  () => effectiveCodes.value.find((code) => isReservedCode(code)) || ''
)
/** 被授权人是本人：后端只禁自审、不禁自授——但这条申请提交后必须由他人签批 */
const isSelfTarget = computed(() => {
  const id = String(createForm.targetUserId || '').trim()
  return Boolean(id) && authStore.isSelf(id)
})
const approvalPolicy = computed(() => approvalPolicyOf(effectiveCodes.value))
const durationOutOfRange = computed(() => {
  const raw = String(createForm.durationHours ?? '').trim()
  if (!raw) return false
  const hours = Number(raw)
  return !Number.isInteger(hours) || hours < MIN_GRANT_HOURS || hours > MAX_GRANT_HOURS
})
const estimatedExpiry = computed(() => {
  const hours = Number(createForm.durationHours)
  // 越界值不给「预计到期」：那等于替一个会被 400 拒绝的时长背书
  if (!Number.isInteger(hours) || hours < MIN_GRANT_HOURS || hours > MAX_GRANT_HOURS) return ''
  return formatTime(new Date(nowTick.value + hours * 3600 * 1000))
})
const submitHint = computed(() =>
  t('privilegeGrant.submitHint', { count: approvalPolicy.value.requiredApprovals })
)

const filteredPermissionGroups = computed(() => {
  const kw = permSearch.value.trim().toLowerCase()
  if (!kw) return permissionGroups.value
  return permissionGroups.value
    .map((group) => ({
      ...group,
      permissions: group.permissions.filter((perm) => {
        const label = permissionName(perm)
        return (
          String(label).toLowerCase().includes(kw) ||
          String(perm.name || '')
            .toLowerCase()
            .includes(kw) ||
          String(perm.code || '')
            .toLowerCase()
            .includes(kw)
        )
      }),
    }))
    .filter((group) => group.permissions.length > 0)
})

const permissionIcon = (module) =>
  ({
    system: '⚙️',
    user: '👤',
    role: '🔑',
    permission: '🛡️',
    device: '🔧',
    alarm: '🚨',
    inspection: '📋',
    report: '📊',
    security: '🛡️',
    privilege: '🎫',
    pii: '🔒',
  })[module] || '📦'

const moduleName = (group) => {
  const key = {
    system: 'nav.system',
    user: 'nav.users',
    role: 'nav.roles',
    permission: 'role.permissions',
    device: 'nav.devices',
    alarm: 'nav.alarms',
    inspection: 'nav.inspections',
    report: 'nav.reports',
    security: 'security.title',
    privilege: 'nav.privilegeGrants',
    pii: 'privilegeGrant.modulePii',
  }[group.module]
  const translated = key ? t(key) : ''
  return translated && translated !== key ? translated : group.name || group.module
}

const userLabel = (user) =>
  [user?.username, user?.realName, user?.department].filter(Boolean).join(' · ') || user?._id || ''

const initials = (row) =>
  String(row?.username || '?')
    .slice(0, 1)
    .toUpperCase()

const permissionDisplayName = (code) => {
  const perm = permissionMap.value.get(code)
  return perm ? permissionName(perm) : code
}

const visibleCodes = (row) => (row.permissionCodes || []).slice(0, 2)

/** 签批人数按审批人去重后计数：存量同人重复签批不能凑进进度条（后端判据同尺） */
const approvalCount = (row) =>
  new Set((row.approvals || []).map((approval, index) => String(approval?.by ?? 'i' + index))).size

/** requiredApprovals 兜底：老记录缺字段时按高敏=2 / 常规=1 显示，避免渲染成 0/undefined */
const requiredApprovals = (row) => {
  const value = Number(row?.requiredApprovals)
  if (Number.isFinite(value) && value > 0) return Math.floor(value)
  return row?.highRisk ? 2 : 1
}

const isRequesterRow = (row) => authStore.isSelf(row.requestedBy)
const hasApprovedRow = (row) =>
  (row.approvals || []).some((approval) => authStore.isSelf(approval.by))
const canDecideRow = (row) =>
  row.status === 'pending' && canApprove.value && !isRequesterRow(row) && !hasApprovedRow(row)
const actionHint = (row) => {
  if (row.status !== 'pending' || !canApprove.value) return ''
  if (isRequesterRow(row)) return t('privilegeGrant.selfRequestHint')
  if (hasApprovedRow(row)) return t('privilegeGrant.alreadyApprovedHint')
  return ''
}
const approvalTitle = (row) => {
  const names = (row.approvals || [])
    .map((approval) => approval.name || approval.by)
    .filter(Boolean)
  if (names.length > 0) return names.join('、')
  return t('privilegeGrant.waitingApprovals', {
    count: Math.max(0, requiredApprovals(row) - approvalCount(row)),
  })
}

const REMAINING_LABEL_KEYS = {
  minutes: 'privilegeGrant.remainingMinutes',
  hours: 'privilegeGrant.remainingHours',
  days: 'privilegeGrant.remainingDays',
}

/** 剩余时间：读侧按 nowTick 走；无法解析的 expiresAt 按已到期显示（fail-closed） */
const remainingLabel = (row) => {
  if (!row.expiresAt) return t('privilegeGrant.notEffectiveYet')
  const remaining = remainingOf(row.expiresAt, nowTick.value)
  if (!remaining || remaining.kind === 'expired') return t('privilegeGrant.expiredLabel')
  return t(REMAINING_LABEL_KEYS[remaining.kind], { count: remaining.count })
}

/** 生效态看 expiresAt 而不是库内 status：回收任务滞后时 active 记录其实已失效 */
const displayStatus = (row) => effectiveStatusOf(row, nowTick.value)
const detailStatus = computed(() => effectiveStatusOf(detailGrant.value, nowTick.value))

const rowClassName = ({ row }) =>
  row.status === 'pending' && canDecideRow(row) ? 'is-actionable' : ''

const summaryCardClass = (card) => [
  'summary-card',
  'summary-card--' + card.tone,
  { 'is-active': card.active },
]
const permissionOptionClass = (perm) => ({
  'is-selected': isCodeSelected(perm.code),
  'is-high-risk': isHighRiskCode(perm.code),
})

const emptyTitle = computed(() =>
  statusFilter.value === 'pending' ? t('privilegeGrant.emptyPending') : t('privilegeGrant.empty')
)
const emptyHint = computed(() =>
  statusFilter.value === 'pending'
    ? t('privilegeGrant.emptyPendingHint')
    : t('privilegeGrant.emptyHint')
)

const overdueGrants = computed(() => summary.value?.overdueGrants || [])
const daysSince = (value) => {
  const time = new Date(value).getTime()
  if (!Number.isFinite(time)) return 0
  return Math.max(0, Math.floor((nowTick.value - time) / 86400000))
}

const loadData = async () => {
  const isCurrent = listGuard()
  loading.value = true
  try {
    const res = await api.permissions.getGrants({
      status: statusFilter.value || undefined,
      page: page.current,
      limit: page.size,
    })
    if (!isCurrent()) return
    const payload = res?.data?.data
    rows.value = Array.isArray(payload) ? payload : []
    // WF-06（2026-11-02 核对）：本视图未接三态契约（页头 loadError 承担等价语义），
    // total 保持数字域；兜底改 ?? —— total=0 是合法值，|| 会让"删空后的 0 条"
    // 被当前页长度顶替成假总数（与下方 clamp 的 lastPage 计算互相矛盾）。
    page.total = res?.data?.pagination?.total ?? rows.value.length
    loadError.value = false
    // 撤销/驳回掉末页最后一条后，当前页可能已越过末页：回退到最后一页再拉一次，
    // 否则用户停在一个永远空白的页上，看起来像「数据没了」
    if (isCurrent() && rows.value.length === 0 && page.total > 0 && page.current > 1) {
      const lastPage = Math.max(1, Math.ceil(page.total / page.size))
      if (lastPage < page.current) {
        page.current = lastPage
        await loadData()
        return
      }
    }
  } catch (e) {
    if (isCanceledError(e)) return
    if (!isCurrent()) return
    loadError.value = true
    if (rows.value.length === 0) page.total = 0
  } finally {
    if (isCurrent()) loading.value = false
  }
}

const loadSummary = async () => {
  try {
    const res = await api.permissions.getGrantReview()
    summary.value = res?.data?.data || null
    summaryFailed.value = false
  } catch (e) {
    if (isCanceledError(e)) return
    // 失败即未知：保留 summary=null 让卡片走 '—' 分支，并单独标记错误态；
    // 此前这里只置 null，模板 v-if 把整块摘要摘掉——复核汇总静默消失，连计数都没了。
    summary.value = null
    summaryFailed.value = true
    // 拦截器已按具体状态码提示过的不再重复；没有提示的（非 axios 异常）必须留一条 warn，
    // 否则这条链路失败后没有任何痕迹。
    if (!isHandledApiError(e)) ElMessage.warning(t('privilegeGrant.summaryLoadFailed'))
  }
}

const loadAll = () => Promise.all([loadData(), loadSummary()])

const handleStatusChange = () => {
  page.current = 1
  loadData()
}

const setStatus = (status) => {
  if (statusFilter.value === status) return
  statusFilter.value = status
  handleStatusChange()
}

const handleSummaryCard = (card) => {
  if (card.key === 'overdue') {
    overdueVisible.value = true
    return
  }
  setStatus(card.targetStatus)
}

const handleSizeChange = () => {
  page.current = 1
  loadData()
}

/** 记住加载过的用户对象：远程搜索换页后，已选中的用户仍要显示姓名而不是裸 _id */
const rememberUsers = (list) => {
  list.forEach((user) => userCache.value.set(String(user._id), user))
  return list
}

/**
 * 候选用户加载：keyword 为空时拉首页（进表单即可直接点选常用用户），
 * 有关键词时走服务端 search（用户名前缀 / 姓名子串 / 邮箱片段）；
 * 用户数超过单页上限时，没有服务端搜索就根本找不到目标用户。
 * 刻意不传 AbortSignal：并发由门票丢弃；若把取消当正常返回，
 * 控件会永久停在 loading（取消分支既不落数据也不复位状态）。
 */
const loadUserOptions = async (keyword) => {
  if (!hasPerm('user:read') || typeof api.users?.getList !== 'function') {
    usersState.value = 'unavailable'
    return
  }
  const term = String(keyword || '').trim()
  const isCurrent = userSearchGuard()
  const firstLoad = usersState.value !== 'ready'
  if (firstLoad) usersState.value = 'loading'
  else userSearching.value = true
  try {
    const res = await api.users.getList(
      {
        status: 'active',
        page: 1,
        limit: USER_SEARCH_LIMIT,
        ...(term ? { search: term } : {}),
      },
      { silentErrors: true }
    )
    if (!isCurrent()) return
    const payload = res?.data?.data
    userOptions.value = rememberUsers(
      Array.isArray(payload)
        ? payload
            .filter((user) => user && user._id)
            .sort((a, b) => String(a.username || '').localeCompare(String(b.username || '')))
        : []
    )
    userSearchFailed.value = false
    if (firstLoad) usersState.value = userOptions.value.length > 0 ? 'ready' : 'empty'
  } catch (e) {
    if (isCanceledError(e) || !isCurrent()) return
    if (firstLoad) {
      // 首次加载失败（缺 user:read 或接口不可用）：退回手填用户 ID
      usersState.value = 'unavailable'
      return
    }
    // 搜索失败清空候选：宁可让用户重试，也不能留着上一个关键词的结果让人误选
    userOptions.value = []
    userSearchFailed.value = true
  } finally {
    if (isCurrent()) userSearching.value = false
  }
}

const flattenPermissionNodes = (nodes, module, acc = [], seen = new Set()) => {
  for (const node of nodes || []) {
    if (!node) continue
    const id = String(node._id || '')
    if (/^[0-9a-fA-F]{24}$/.test(id) && node.code && !seen.has(node.code)) {
      seen.add(node.code)
      acc.push({ ...node, module: node.module || module })
    }
    flattenPermissionNodes(node.children, module, acc, seen)
  }
  return acc
}

const loadPermissionCatalog = async () => {
  if (permissionState.value === 'loading' || permissionState.value === 'ready') return
  if (
    !(hasPerm('permission:read') || hasPerm('permission:tree')) ||
    typeof api.roles?.getPermissionTree !== 'function'
  ) {
    permissionState.value = 'unavailable'
    return
  }
  permissionState.value = 'loading'
  try {
    const res = await api.roles.getPermissionTree({ silentErrors: true })
    const tree = res?.data?.data
    const rawGroups = (Array.isArray(tree) ? tree : []).filter(Boolean).map((mod) => ({
      module: mod.module,
      name: moduleName(mod),
      icon: permissionIcon(mod.module),
      permissions: flattenPermissionNodes(mod.children, mod.module),
    }))
    const map = new Map()
    rawGroups.forEach((group) => group.permissions.forEach((perm) => map.set(perm.code, perm)))
    permissionMap.value = map
    // 保留通配权限（*:*）在目录里存在、但任何授予入口都会拒绝：不渲染成选项，
    // 避免「点得中、提交才 400」。名称映射仍保留，老记录的详情才能显示名字
    const groups = rawGroups
      .map((group) => ({
        ...group,
        permissions: group.permissions.filter((perm) => !isReservedCode(perm.code)),
      }))
      .filter((group) => group.permissions.length > 0)
    permissionGroups.value = groups
    permissionState.value = groups.length > 0 ? 'ready' : 'empty'
  } catch (e) {
    if (isCanceledError(e)) return
    permissionState.value = 'unavailable'
  }
}

const ensureOptions = () => {
  loadUserOptions()
  loadPermissionCatalog()
}

const toggleCreate = () => {
  creating.value = !creating.value
  if (!creating.value) return
  // 展开授权面板=一次新的提交意图，换新键（上一次的键已用于生成过申请）
  submission.renew()
  ensureOptions()
  nextTick(() => {
    const panel = document.querySelector('.create-form')
    if (panel && typeof panel.scrollIntoView === 'function') {
      panel.scrollIntoView({ behavior: 'smooth', block: 'start' })
    }
  })
}

const isCodeSelected = (code) => selectedPermissionCodes.value.includes(code)

const togglePermissionCode = (code) => {
  const current = selectedPermissionCodes.value
  if (current.includes(code)) {
    createForm.permissionCodes = current.filter((item) => item !== code)
    return
  }
  if (current.length >= MAX_GRANT_CODES) {
    ElMessage.warning(t('privilegeGrant.permissionLimit', { max: MAX_GRANT_CODES }))
    return
  }
  createForm.permissionCodes = [...current, code]
}

const isGroupFullySelected = (group) =>
  group.permissions.length > 0 && group.permissions.every((perm) => isCodeSelected(perm.code))

const togglePermissionGroup = (group) => {
  const allSelected = isGroupFullySelected(group)
  if (allSelected) {
    const groupCodes = new Set(group.permissions.map((perm) => perm.code))
    createForm.permissionCodes = selectedPermissionCodes.value.filter(
      (code) => !groupCodes.has(code)
    )
    return
  }
  const next = [...selectedPermissionCodes.value]
  for (const perm of group.permissions) {
    if (next.length >= MAX_GRANT_CODES) {
      ElMessage.warning(t('privilegeGrant.permissionLimit', { max: MAX_GRANT_CODES }))
      break
    }
    if (!next.includes(perm.code)) next.push(perm.code)
  }
  createForm.permissionCodes = next
}

const setDuration = (hours) => {
  createForm.durationHours = hours
}

const resetCreateForm = () => {
  createForm.targetUserId = ''
  createForm.permissionCodes = []
  createForm.durationHours = 8
  createForm.reason = ''
  manualCodesText.value = ''
  permSearch.value = ''
  userSearchFailed.value = false
}

const handleCreate = async () => {
  if (submitting.value) return
  const targetUserId = String(createForm.targetUserId || '').trim()
  if (!targetUserId) {
    ElMessage.warning(t('privilegeGrant.targetUserRequired'))
    return
  }
  if (!/^[0-9a-fA-F]{24}$/.test(targetUserId)) {
    ElMessage.warning(t('privilegeGrant.targetUserInvalid'))
    return
  }
  const codes = effectiveCodes.value
  if (codes.length === 0) {
    ElMessage.warning(t('privilegeGrant.codesRequired'))
    return
  }
  const reserved = codes.find((code) => isReservedCode(code))
  if (reserved) {
    ElMessage.warning(t('privilegeGrant.reservedCodeBlocked', { code: reserved }))
    return
  }
  if (codes.length > MAX_GRANT_CODES) {
    ElMessage.warning(t('privilegeGrant.permissionLimit', { max: MAX_GRANT_CODES }))
    return
  }
  const hours = Number(createForm.durationHours)
  if (
    !Number.isFinite(hours) ||
    !Number.isInteger(hours) ||
    hours < MIN_GRANT_HOURS ||
    hours > MAX_GRANT_HOURS
  ) {
    ElMessage.warning(
      t('privilegeGrant.durationInvalid', { min: MIN_GRANT_HOURS, max: MAX_GRANT_HOURS })
    )
    return
  }
  if (!createForm.reason.trim()) {
    ElMessage.warning(t('privilegeGrant.reasonRequired'))
    return
  }

  submitting.value = true
  try {
    const res = await api.permissions.createGrant(
      {
        targetUserId,
        permissionCodes: codes,
        durationHours: hours,
        reason: createForm.reason.trim(),
      },
      { headers: submission.header() }
    )
    const payload = res?.data?.data || {}
    ElMessage.success(
      payload.requiredApprovals > 1
        ? t('privilegeGrant.createdHighRisk', { count: payload.requiredApprovals })
        : t('privilegeGrant.created')
    )
    creating.value = false
    resetCreateForm()
    statusFilter.value = 'pending'
    page.current = 1
    loadAll()
  } catch (e) {
    // 拦截器已就 HTTP/网络错误弹过具体原因：这里只兜非 axios 异常，避免一次失败弹两条
    if (!isHandledApiError(e)) ElMessage.error(t('messages.requestFailed'))
  } finally {
    submitting.value = false
  }
}

const runDecision = async (row, action) => {
  if (decidingId.value !== null) return
  decidingId.value = row._id
  try {
    await action(row)
  } catch (e) {
    // 失败多半是库内状态已变（被他人处理 / 已撤销 / 会话过期）：提示后照样刷新列表，
    // 否则用户会对着一条早已失效的行反复点击（旧实现里异常还会冒成未处理的 rejection）
    if (!isHandledApiError(e)) ElMessage.error(t('messages.requestFailed'))
  } finally {
    decidingId.value = null
  }
  loadAll()
}

const handleApprove = (row) =>
  runDecision(row, async (target) => {
    const res = await api.permissions.approveGrant(target._id)
    const status = res?.data?.data?.status
    ElMessage.success(
      status === 'active'
        ? t('privilegeGrant.approvedActive')
        : status === 'pending'
          ? t('privilegeGrant.approvedWaiting')
          : t('privilegeGrant.approved')
    )
  })

const handleReject = async (row) => {
  const reason = await ElMessageBox.prompt(
    t('privilegeGrant.rejectPrompt', { user: row.username || row.userId }),
    t('privilegeGrant.rejectTitle'),
    {
      confirmButtonText: t('common.confirm'),
      cancelButtonText: t('common.cancel'),
      inputType: 'textarea',
      inputPlaceholder: t('privilegeGrant.reasonPlaceholder'),
    }
  ).catch(() => null)
  if (!reason || reason.action !== 'confirm') return
  return runDecision(row, async (target) => {
    await api.permissions.rejectGrant(target._id, { reason: reason.value || '' })
    ElMessage.success(t('privilegeGrant.rejected'))
  })
}

const handleRevoke = async (row) => {
  const ok = await ElMessageBox.confirm(
    t('privilegeGrant.revokeConfirm', {
      user: row.username || row.userId,
      count: (row.permissionCodes || []).length,
    }),
    t('privilegeGrant.revokeTitle'),
    {
      confirmButtonText: t('common.confirm'),
      cancelButtonText: t('common.cancel'),
      type: 'warning',
    }
  ).catch(() => null)
  if (!ok) return
  return runDecision(row, async (target) => {
    await api.permissions.revokeGrant(target._id)
    ElMessage.success(t('privilegeGrant.revoked'))
  })
}

const openDetails = async (row) => {
  detailGrant.value = row
  detailVisible.value = true
  await loadPermissionCatalog()
}

const handleWithdraw = async (row) => {
  const ok = await ElMessageBox.confirm(
    t('privilegeGrant.withdrawConfirm', { user: row.username || row.userId }),
    t('privilegeGrant.withdrawTitle'),
    {
      confirmButtonText: t('common.confirm'),
      cancelButtonText: t('common.cancel'),
      type: 'warning',
    }
  ).catch(() => null)
  if (!ok) return
  return runDecision(row, async (target) => {
    await api.permissions.revokeGrant(target._id)
    ElMessage.success(t('privilegeGrant.withdrawn'))
  })
}

const openOverdueDetails = (row) => {
  overdueVisible.value = false
  openDetails(row)
}

const detailTimeline = computed(() => {
  const grant = detailGrant.value
  if (!grant) return []
  const items = [
    {
      key: 'requested',
      title: t('privilegeGrant.requestedStep', { name: grant.requestedByName || '-' }),
      time: grant.requestedAt,
      tone: 'done',
    },
  ]
  for (const [index, approval] of (grant.approvals || []).entries()) {
    items.push({
      key: 'approval-' + index,
      title: t('privilegeGrant.approvalStep', { name: approval.name || approval.by }),
      time: approval.at,
      tone: 'done',
    })
  }
  if (detailStatus.value === 'pending') {
    items.push({
      key: 'waiting',
      title: t('privilegeGrant.pendingStep', {
        count: Math.max(1, requiredApprovals(grant) - approvalCount(grant)),
      }),
      tone: 'pending',
    })
  }
  if (grant.grantedAt) {
    items.push({
      key: 'granted',
      title: t('privilegeGrant.activeStep'),
      time: grant.grantedAt,
      tone: 'done',
    })
  }
  // 撤销事件：标题带撤销人、时间取 revokedAt、说明取 revokeReason。
  // 旧实现整条时间线只读 decisionReason，撤销后界面上看不到「谁在什么时候撤的、为什么」。
  if (detailStatus.value === 'revoked') {
    items.push({
      key: 'revoked',
      title: t('privilegeGrant.revokedStep', { name: grant.revokedByName || '-' }),
      time: grant.revokedAt,
      detail: grant.revokeReason || '',
      tone: 'muted',
    })
  }
  if (grant.decisionReason) {
    items.push({
      key: 'decision',
      title: t('privilegeGrant.decisionReason'),
      detail: grant.decisionReason,
      tone: 'muted',
    })
  }
  if (detailStatus.value === 'expired') {
    items.push({
      key: 'expired',
      title: t('privilegeGrant.statusExpired'),
      time: grant.expiresAt,
      tone: 'muted',
    })
  }
  return items
})

onMounted(() => {
  loadAll()
  tickTimer = setInterval(() => {
    nowTick.value = Date.now()
  }, 30000)
})

onUnmounted(() => {
  if (tickTimer) {
    clearInterval(tickTimer)
    tickTimer = null
  }
})
</script>

<style scoped>
.page {
  display: flex;
  flex-direction: column;
  gap: var(--xf-spacing-lg);
}

.grant-hero {
  position: relative;
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  gap: var(--xf-spacing-xl);
  overflow: hidden;
  padding: 28px 30px;
  border: 1px solid var(--xf-border-glass);
  border-radius: var(--xf-radius-xl);
  background:
    radial-gradient(circle at 92% 18%, var(--xf-primary-alpha-12), transparent 32%),
    linear-gradient(135deg, rgba(255, 255, 255, 0.9), rgba(248, 250, 252, 0.72));
  box-shadow: var(--xf-shadow-md);
}

.grant-hero::after {
  content: '';
  position: absolute;
  inset: auto 0 0 0;
  height: 3px;
  background: var(--xf-gradient-primary);
  opacity: 0.72;
}

.grant-hero__copy {
  max-width: 760px;
}

.grant-eyebrow {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  margin-bottom: 8px;
  color: var(--xf-primary-strong);
  font-size: 11px;
  font-weight: 700;
  letter-spacing: var(--xf-tracking-wider);
  text-transform: uppercase;
}

.grant-eyebrow__dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: var(--xf-primary);
  box-shadow: 0 0 0 4px var(--xf-primary-alpha-12);
}

.grant-hero__title {
  margin: 0 0 6px;
  color: var(--xf-gray-900);
  font-family: var(--xf-font-display);
  font-size: 27px;
  font-weight: 700;
  letter-spacing: var(--xf-tracking-tight);
}

.grant-hero__subtitle {
  max-width: 700px;
  margin: 0;
  color: var(--xf-text-secondary);
  font-size: 14px;
  line-height: 1.7;
}

.rule-chips {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-top: 16px;
}

.rule-chip {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 5px 10px;
  border: 1px solid var(--xf-border-color);
  border-radius: 999px;
  background: rgba(255, 255, 255, 0.62);
  color: var(--xf-text-secondary);
  font-size: 11px;
  font-weight: 600;
}

.rule-chip .el-icon {
  color: var(--xf-primary);
}

.grant-hero__actions {
  flex: none;
  padding-bottom: 2px;
}

.grant-cta {
  min-width: 150px;
}

.summary-grid {
  display: grid;
  grid-template-columns: repeat(5, minmax(0, 1fr));
  gap: 10px;
}

.summary-failed {
  display: flex;
  align-items: center;
  gap: 8px;
  margin: 8px 0 4px;
  padding: 8px 12px;
  border-radius: 10px;
  border: 1px solid rgba(230, 162, 60, 0.35);
  background: rgba(230, 162, 60, 0.12);
  color: #b88230;
  font-size: 13px;
}

.summary-failed__text {
  flex: 1;
}

.summary-card {
  display: flex;
  min-width: 0;
  flex-direction: column;
  align-items: flex-start;
  gap: 1px;
  padding: 14px 16px;
  border: 1px solid var(--xf-border-glass);
  border-radius: var(--xf-radius-lg);
  background: rgba(255, 255, 255, 0.56);
  color: var(--xf-text-regular);
  text-align: left;
  cursor: pointer;
  box-shadow: var(--xf-shadow-xs);
  transition:
    transform var(--xf-duration-base) var(--xf-ease-standard),
    box-shadow var(--xf-duration-base) var(--xf-ease-standard),
    border-color var(--xf-duration-base) var(--xf-ease-standard);
}

.summary-card:hover {
  transform: translateY(-2px);
  border-color: var(--xf-border-glass-strong);
  box-shadow: var(--xf-shadow-md);
}

.summary-card.is-active {
  border-color: var(--xf-primary-alpha-45);
  box-shadow:
    0 0 0 2px var(--xf-primary-alpha-8),
    var(--xf-shadow-sm);
}

.summary-card__top {
  display: flex;
  width: 100%;
  align-items: center;
  justify-content: space-between;
}

.summary-value {
  color: var(--xf-gray-900);
  font-family: var(--xf-font-display);
  font-size: 25px;
  font-weight: 700;
  line-height: 1.2;
}

.summary-card__icon {
  color: var(--xf-gray-400);
  font-size: 16px;
}

.summary-card--warning .summary-card__icon {
  color: var(--xf-warning);
}

.summary-card--success .summary-card__icon {
  color: var(--xf-success);
}

.summary-card--danger .summary-card__icon {
  color: var(--xf-danger);
}

.summary-card--info .summary-card__icon {
  color: var(--xf-info);
}

.summary-label {
  color: var(--xf-text-secondary);
  font-size: 12px;
  font-weight: 600;
}

.summary-hint {
  overflow: hidden;
  width: 100%;
  color: var(--xf-text-muted);
  font-size: 10px;
  line-height: 1.4;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.create-form {
  padding: 22px 24px;
  border: 1px solid var(--xf-primary-alpha-15);
  border-radius: var(--xf-radius-xl);
  background: linear-gradient(135deg, rgba(255, 255, 255, 0.94), rgba(255, 248, 246, 0.82));
  box-shadow: var(--xf-shadow-lg);
  animation: page-enter 0.25s var(--xf-ease-glass) both;
}

.create-form__header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
  padding-bottom: 16px;
  border-bottom: 1px solid var(--xf-border-color);
}

.create-form__title {
  margin: 0 0 3px;
  color: var(--xf-gray-900);
  font-family: var(--xf-font-display);
  font-size: 20px;
  font-weight: 700;
}

.create-form__subtitle {
  margin: 0;
  color: var(--xf-text-secondary);
  font-size: 12px;
}

.icon-btn {
  display: inline-flex;
  width: 34px;
  height: 34px;
  flex: none;
  align-items: center;
  justify-content: center;
  border: 1px solid var(--xf-border-color);
  border-radius: 50%;
  background: rgba(255, 255, 255, 0.52);
  color: var(--xf-text-secondary);
  cursor: pointer;
  transition:
    background-color var(--xf-duration-base) var(--xf-ease-standard),
    color var(--xf-duration-base) var(--xf-ease-standard);
}

.icon-btn:hover {
  background: var(--xf-gray-100);
  color: var(--xf-primary);
}

.request-layout {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 286px;
  gap: 24px;
  padding-top: 6px;
}

.request-main {
  min-width: 0;
}

.form-section {
  padding: 18px 0;
  border-bottom: 1px solid var(--xf-border-color);
}

.form-section:last-child {
  border-bottom: 0;
  padding-bottom: 6px;
}

.form-section__head {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  margin-bottom: 12px;
}

.step-number {
  display: inline-flex;
  width: 24px;
  height: 24px;
  flex: none;
  align-items: center;
  justify-content: center;
  border-radius: 50%;
  background: var(--xf-primary-alpha-8);
  color: var(--xf-primary-strong);
  font-size: 12px;
  font-weight: 700;
}

.form-section__head h3 {
  margin: 0 0 2px;
  color: var(--xf-gray-800);
  font-size: 14px;
  font-weight: 700;
}

.form-section__head p {
  margin: 0;
  color: var(--xf-text-muted);
  font-size: 11px;
  line-height: 1.5;
}

.form-control {
  max-width: 420px;
}

.form-control--full {
  width: 100%;
  max-width: 620px;
}

.form-control--narrow {
  width: 170px;
}

.field-help {
  display: flex;
  min-height: 20px;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
  margin-top: 6px;
  font-size: 11px;
}

.field-help__muted {
  color: var(--xf-text-muted);
}

.selected-user {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  color: var(--xf-success-strong);
  font-weight: 600;
}

.selected-user__dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--xf-success);
}

.text-link {
  padding: 0;
  border: 0;
  background: transparent;
  color: var(--xf-primary);
  font-size: 11px;
  cursor: pointer;
}

.text-link:hover {
  text-decoration: underline;
}

.user-option {
  display: flex;
  align-items: center;
  gap: 8px;
}

.user-option__avatar,
.user-cell__avatar {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  flex: none;
  border-radius: 50%;
  background: var(--xf-primary-alpha-8);
  color: var(--xf-primary-strong);
  font-weight: 700;
}

.user-option__avatar {
  width: 28px;
  height: 28px;
  font-size: 12px;
}

.user-option__main {
  display: flex;
  min-width: 0;
  flex: 1;
  flex-direction: column;
  line-height: 1.25;
}

.user-option__main strong {
  color: var(--xf-gray-800);
  font-size: 12px;
}

.user-option__main small {
  overflow: hidden;
  color: var(--xf-text-muted);
  font-size: 10px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.permission-toolbar {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 12px;
}

.permission-search {
  max-width: 360px;
}

.permission-count {
  color: var(--xf-text-muted);
  font-size: 11px;
  white-space: nowrap;
}

.permission-groups {
  display: flex;
  max-height: 310px;
  flex-direction: column;
  gap: 12px;
  overflow: auto;
  padding-right: 4px;
}

.permission-group {
  padding: 10px 12px;
  border: 1px solid var(--xf-border-color);
  border-radius: var(--xf-radius-md);
  background: rgba(255, 255, 255, 0.48);
}

.permission-group__head {
  display: flex;
  align-items: center;
  gap: 7px;
  margin-bottom: 8px;
}

.permission-group__icon {
  font-size: 13px;
}

.permission-group__name {
  flex: 1;
  color: var(--xf-gray-700);
  font-size: 12px;
  font-weight: 700;
}

.permission-group__toggle {
  flex: none;
}

.permission-options {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.permission-option {
  position: relative;
  display: inline-flex;
  max-width: 100%;
  align-items: center;
  gap: 6px;
  padding: 6px 8px;
  border: 1px solid var(--xf-border-color);
  border-radius: 9px;
  background: rgba(255, 255, 255, 0.68);
  cursor: pointer;
  transition:
    border-color var(--xf-duration-base) var(--xf-ease-standard),
    background-color var(--xf-duration-base) var(--xf-ease-standard),
    box-shadow var(--xf-duration-base) var(--xf-ease-standard);
}

.permission-option:hover {
  border-color: var(--xf-primary-alpha-35);
  background: #fff;
}

.permission-option.is-selected {
  border-color: var(--xf-primary-alpha-45);
  background: var(--xf-primary-alpha-8);
  box-shadow: inset 0 0 0 1px var(--xf-primary-alpha-8);
}

.permission-option.is-high-risk:not(.is-selected) {
  border-style: dashed;
}

.permission-option__input {
  position: absolute;
  width: 1px;
  height: 1px;
  opacity: 0;
  pointer-events: none;
}

.permission-option__check {
  display: inline-flex;
  width: 15px;
  height: 15px;
  flex: none;
  align-items: center;
  justify-content: center;
  border: 1px solid var(--xf-border-color-strong);
  border-radius: 4px;
  background: #fff;
  color: #fff;
  font-size: 10px;
  font-weight: 700;
}

.permission-option.is-selected .permission-option__check {
  border-color: var(--xf-primary);
  background: var(--xf-primary);
}

.permission-option__input:focus-visible + .permission-option__check {
  outline: 2px solid var(--xf-primary-alpha-45);
  outline-offset: 1px;
}

.permission-option__body {
  display: flex;
  min-width: 0;
  flex-direction: column;
  line-height: 1.25;
}

.permission-option__name {
  overflow: hidden;
  max-width: 180px;
  color: var(--xf-gray-700);
  font-size: 11px;
  font-weight: 600;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.permission-option__code {
  overflow: hidden;
  max-width: 180px;
  color: var(--xf-text-muted);
  font-family: var(--xf-font-mono);
  font-size: 9px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.permission-option__risk {
  flex: none;
  padding: 1px 5px;
  border-radius: 999px;
  background: var(--xf-warning-alpha-15);
  color: var(--xf-warning-strong);
  font-size: 9px;
  font-weight: 700;
}

.permission-empty {
  padding: 20px;
  color: var(--xf-text-muted);
  font-size: 12px;
  text-align: center;
}

.selected-codes {
  display: flex;
  flex-wrap: wrap;
  gap: 5px;
  margin-top: 9px;
}

.selected-code {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 3px 7px;
  border-radius: 6px;
  background: var(--xf-gray-100);
  color: var(--xf-text-secondary);
  font-family: var(--xf-font-mono);
  font-size: 10px;
}

.selected-code__remove {
  display: inline-flex;
  width: 14px;
  height: 14px;
  align-items: center;
  justify-content: center;
  border: 0;
  border-radius: 50%;
  background: transparent;
  color: var(--xf-text-muted);
  font-size: 13px;
  line-height: 1;
  cursor: pointer;
}

.selected-code__remove:hover {
  background: var(--xf-danger-alpha-8);
  color: var(--xf-danger);
}

.duration-presets {
  display: flex;
  flex-wrap: wrap;
  gap: 7px;
  margin-bottom: 10px;
}

.duration-preset {
  padding: 6px 12px;
  border: 1px solid var(--xf-border-color);
  border-radius: 999px;
  background: rgba(255, 255, 255, 0.66);
  color: var(--xf-text-secondary);
  font-size: 11px;
  font-weight: 600;
  cursor: pointer;
  transition:
    background-color var(--xf-duration-base) var(--xf-ease-standard),
    border-color var(--xf-duration-base) var(--xf-ease-standard),
    color var(--xf-duration-base) var(--xf-ease-standard);
}

.duration-preset:hover {
  border-color: var(--xf-primary-alpha-35);
  color: var(--xf-primary);
}

.duration-preset.is-active {
  border-color: var(--xf-primary);
  background: var(--xf-primary);
  color: #fff;
}

.duration-custom {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 10px;
}

.duration-custom__hint {
  color: var(--xf-text-muted);
  font-size: 11px;
}

.expiry-preview {
  display: flex;
  align-items: flex-start;
  gap: 7px;
  margin-top: 11px;
  padding: 8px 10px;
  border-radius: 8px;
  background: var(--xf-info-alpha-8);
  color: var(--xf-info-strong);
  font-size: 11px;
  line-height: 1.5;
}

.expiry-preview .el-icon {
  margin-top: 2px;
  flex: none;
}

.expiry-preview small {
  display: block;
  color: var(--xf-text-muted);
  font-size: 10px;
}

.request-preview {
  position: sticky;
  top: 86px;
  align-self: start;
  padding: 16px;
  border: 1px solid var(--xf-border-color);
  border-radius: var(--xf-radius-lg);
  background: rgba(248, 250, 252, 0.78);
}

.request-preview__head {
  display: flex;
  flex-direction: column;
  gap: 2px;
  margin-bottom: 12px;
}

.request-preview__eyebrow {
  color: var(--xf-gray-800);
  font-size: 12px;
  font-weight: 700;
}

.request-preview__hint {
  color: var(--xf-text-muted);
  font-size: 10px;
}

.preview-list {
  display: flex;
  flex-direction: column;
  gap: 9px;
  margin: 0;
}

.preview-row {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 10px;
  font-size: 11px;
}

.preview-row dt {
  flex: none;
  color: var(--xf-text-muted);
}

.preview-row dd {
  margin: 0;
  color: var(--xf-gray-700);
  font-weight: 600;
  text-align: right;
  word-break: break-all;
}

.preview-row dd.is-warning {
  color: var(--xf-warning-strong);
}

.preview-codes {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
  margin-top: 12px;
  padding-top: 12px;
  border-top: 1px dashed var(--xf-border-color);
}

.preview-code,
.preview-more {
  padding: 2px 6px;
  border-radius: 5px;
  background: var(--xf-gray-100);
  color: var(--xf-text-secondary);
  font-family: var(--xf-font-mono);
  font-size: 9px;
}

.preview-more {
  color: var(--xf-text-muted);
}

.preview-warning {
  display: flex;
  align-items: flex-start;
  gap: 6px;
  margin-top: 12px;
  padding-top: 11px;
  border-top: 1px dashed var(--xf-warning-alpha-30);
  color: var(--xf-warning-strong);
  font-size: 10px;
  line-height: 1.5;
}

.preview-warning .el-icon {
  margin-top: 2px;
  flex: none;
}

.preview-note {
  display: flex;
  align-items: flex-start;
  gap: 6px;
  margin-top: 12px;
  padding-top: 11px;
  border-top: 1px dashed var(--xf-border-color);
  color: var(--xf-text-muted);
  font-size: 10px;
  line-height: 1.5;
}

.preview-note .el-icon {
  margin-top: 2px;
  flex: none;
}

.create-form__footer {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding-top: 16px;
  border-top: 1px solid var(--xf-border-color);
}

.submit-hint {
  color: var(--xf-text-muted);
  font-size: 11px;
}

.table-card {
  min-width: 0;
  padding: 18px 20px 12px;
}

.table-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  flex-wrap: wrap;
  margin-bottom: var(--xf-spacing-md);
}

.toolbar-left {
  display: flex;
  min-width: 0;
  align-items: center;
  gap: var(--xf-spacing-md);
}

.user-cell {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  min-width: 0;
}

.user-cell__avatar {
  width: 24px;
  height: 24px;
  font-size: 11px;
}

.user-cell__name {
  overflow: hidden;
  color: var(--xf-gray-800);
  font-size: 12px;
  font-weight: 600;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.code-tag {
  margin: 2px 4px 2px 0;
}

.approval-cell {
  display: flex;
  align-items: center;
  gap: 7px;
}

.approval-count {
  color: var(--xf-gray-700);
  font-family: var(--xf-font-mono);
  font-size: 11px;
  font-weight: 700;
}

.approval-dots {
  display: inline-flex;
  gap: 3px;
}

.approval-dots i {
  display: block;
  width: 5px;
  height: 5px;
  border-radius: 50%;
  background: var(--xf-gray-200);
}

.approval-dots i.is-filled {
  background: var(--xf-success);
}

.expiry-cell {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.expiry-remaining {
  color: var(--xf-warning-strong);
  font-size: 9px;
}

.action-group {
  flex-wrap: nowrap;
  white-space: nowrap;
}

.action-hint {
  overflow: hidden;
  max-width: 92px;
  color: var(--xf-text-muted);
  font-size: 10px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

/* 待我签批的行：淡橙底，长列表里一眼定位待办（与斑马纹叠加，色调克制） */
:deep(.el-table .is-actionable td.el-table__cell) {
  background: rgba(217, 119, 6, 0.06);
}

.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 5px;
  padding: 38px 0 34px;
}

.empty-state__icon {
  display: flex;
  width: 48px;
  height: 48px;
  align-items: center;
  justify-content: center;
  margin-bottom: 4px;
  border-radius: 50%;
  background: var(--xf-gray-100);
  font-size: 22px;
  filter: grayscale(0.3);
}

.empty-tip {
  color: var(--xf-gray-700);
  font-size: 13px;
  font-weight: 600;
}

.empty-state__hint {
  margin: 0 0 6px;
  color: var(--xf-text-muted);
  font-size: 11px;
}

.pagination {
  display: flex;
  justify-content: flex-end;
  margin-top: var(--xf-spacing-lg);
}

:deep(.grant-detail-drawer .el-drawer__body) {
  padding: 0;
}

.detail-drawer {
  min-height: 100%;
  padding: 22px 24px 30px;
  background: var(--xf-bg-page);
}

.detail-drawer__header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 12px;
}

.detail-drawer__eyebrow {
  display: block;
  margin-bottom: 3px;
  color: var(--xf-text-muted);
  font-size: 10px;
  font-weight: 700;
  letter-spacing: var(--xf-tracking-wider);
  text-transform: uppercase;
}

.detail-drawer__header h2 {
  margin: 0;
  color: var(--xf-gray-900);
  font-family: var(--xf-font-display);
  font-size: 22px;
}

.detail-status {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 7px;
  margin-bottom: 18px;
}

.detail-status__remaining {
  color: var(--xf-warning-strong);
  font-size: 11px;
}

.detail-section {
  padding: 15px 0;
  border-top: 1px solid var(--xf-border-color);
}

.detail-section h3 {
  margin: 0 0 7px;
  color: var(--xf-text-muted);
  font-size: 10px;
  font-weight: 700;
  letter-spacing: var(--xf-tracking-wide);
  text-transform: uppercase;
}

.detail-primary {
  margin: 0 0 3px;
  color: var(--xf-gray-800);
  font-size: 13px;
  font-weight: 600;
  word-break: break-word;
}

.detail-muted {
  margin: 2px 0;
  color: var(--xf-text-muted);
  font-size: 11px;
  line-height: 1.5;
  word-break: break-all;
}

.detail-codes {
  display: flex;
  flex-wrap: wrap;
  gap: 5px;
}

.detail-reason {
  margin: 0;
  padding: 10px 12px;
  border-left: 3px solid var(--xf-primary-alpha-35);
  border-radius: 0 8px 8px 0;
  background: rgba(255, 255, 255, 0.62);
  color: var(--xf-gray-700);
  font-size: 12px;
  line-height: 1.7;
  white-space: pre-wrap;
}

.timeline {
  display: flex;
  flex-direction: column;
  gap: 12px;
  margin: 0;
  padding: 0;
  list-style: none;
}

.timeline__item {
  display: flex;
  gap: 10px;
}

.timeline__dot {
  width: 7px;
  height: 7px;
  margin-top: 5px;
  flex: none;
  border-radius: 50%;
  background: var(--xf-gray-300);
  box-shadow: 0 0 0 3px var(--xf-gray-100);
}

.timeline__item.is-done .timeline__dot {
  background: var(--xf-success);
  box-shadow: 0 0 0 3px var(--xf-success-alpha-8);
}

.timeline__item.is-pending .timeline__dot {
  background: var(--xf-warning);
  box-shadow: 0 0 0 3px var(--xf-warning-alpha-8);
}

.timeline__item.is-muted .timeline__dot {
  background: var(--xf-gray-400);
}

.timeline__body {
  display: flex;
  min-width: 0;
  flex-direction: column;
  gap: 1px;
}

.timeline__title {
  color: var(--xf-gray-700);
  font-size: 12px;
  font-weight: 600;
}

.timeline__time {
  color: var(--xf-text-muted);
  font-size: 10px;
}

.timeline__detail {
  margin-top: 2px;
  color: var(--xf-text-secondary);
  font-size: 11px;
  line-height: 1.5;
  white-space: pre-wrap;
}

.detail-section--grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;
}

.overdue-dialog__hint {
  margin: 0 0 12px;
  color: var(--xf-text-secondary);
  font-size: 12px;
  line-height: 1.6;
}

.overdue-empty {
  padding: 28px 0;
  color: var(--xf-text-muted);
  font-size: 12px;
  text-align: center;
}

.overdue-list {
  display: flex;
  flex-direction: column;
  gap: 7px;
}

.overdue-item {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 12px;
  border: 1px solid var(--xf-border-color);
  border-radius: 10px;
  background: rgba(255, 255, 255, 0.62);
  color: var(--xf-gray-700);
  text-align: left;
  cursor: pointer;
}

.overdue-item:hover {
  border-color: var(--xf-primary-alpha-35);
  background: #fff;
}

.overdue-item__user {
  min-width: 100px;
  color: var(--xf-gray-800);
  font-size: 12px;
  font-weight: 600;
}

.overdue-item__meta {
  flex: 1;
  color: var(--xf-text-muted);
  font-size: 11px;
}

.overdue-item .el-icon {
  color: var(--xf-text-muted);
}

@media (max-width: 1100px) {
  .request-layout {
    grid-template-columns: 1fr;
  }

  .request-preview {
    position: static;
    order: -1;
  }
}

@media (max-width: 900px) {
  .grant-hero {
    align-items: flex-start;
    flex-direction: column;
    padding: 22px;
  }

  .summary-grid {
    grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
  }

  .grant-hero__title {
    font-size: 23px;
  }

  .create-form {
    padding: 18px;
  }

  .permission-groups {
    max-height: 260px;
  }
}

@media (max-width: 640px) {
  .summary-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .create-form__footer {
    align-items: flex-start;
    flex-direction: column;
  }

  .permission-toolbar {
    align-items: flex-start;
    flex-direction: column;
  }

  .permission-search {
    max-width: none;
  }
}
</style>
