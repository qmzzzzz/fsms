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
import { api, isHandledApiError } from '@/utils/api'
import { createSubmissionKey } from '@/utils/idempotency'
import { formatTime } from '@/utils/datetime'
import { usePermission } from '@/composables/usePermission'
import { usePrivilegeGrantList } from '@/composables/usePrivilegeGrantList'
import { usePrivilegeGrantOptions } from '@/composables/usePrivilegeGrantOptions'
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

const canGrant = computed(() => hasPerm('privilege:grant'))
const canApprove = computed(() => hasPerm('privilege:approve'))

const {
  loading,
  loadError,
  rows,
  summary,
  summaryFailed,
  page,
  statusFilter,
  loadData,
  loadSummary,
  loadAll,
  handleStatusChange,
  setStatus,
  handleSizeChange,
} = usePrivilegeGrantList({ canApprove })

const {
  usersState,
  userOptions,
  userSearching,
  userSearchFailed,
  userCache,
  permissionState,
  permissionGroups,
  permissionMap,
  loadUserOptions,
  loadPermissionCatalog,
  ensureOptions,
  moduleName,
} = usePrivilegeGrantOptions({ hasPerm })

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

const handleSummaryCard = (card) => {
  if (card.key === 'overdue') {
    overdueVisible.value = true
    return
  }
  setStatus(card.targetStatus)
}

/** 记住加载过的用户对象：远程搜索换页后，已选中的用户仍要显示姓名而不是裸 _id */
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
      // P3：镜像后端上限（permissionRoutes.grantReasonValidation：reason optional + max 200）。
      // ElMessageBox.prompt 不支持原生 maxlength，沿用 AlarmView.handleResult 的
      // validator 镜像法：超限拦在本地，不发注定 400 的请求；空值放行与后端 optional 同口径
      inputValidator: (value) =>
        !value || value.trim().length <= 200 || t('privilegeGrant.reasonTooLong'),
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

<style scoped src="./PrivilegeGrantView.css"></style>
