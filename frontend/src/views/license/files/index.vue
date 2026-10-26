<!-- 授权文件管理：在线签发 License 授权文件、下载分发、吊销 -->
<template>
  <div class="license-files-page art-full-height">
    <div class="search-bar">
      <ElForm :model="searchForm" inline class="search-form">
        <ElFormItem label="关键字">
          <ElInput
            v-model="searchForm.keyword"
            placeholder="文件编号 / 授权编号 / 应用"
            clearable
            style="width: 220px"
            @keyup.enter="handleSearch"
          />
        </ElFormItem>
        <ElFormItem label="应用">
          <ElSelect
            v-model="searchForm.appId"
            placeholder="全部"
            clearable
            filterable
            style="width: 180px"
          >
            <ElOption v-for="app in appOptions" :key="app.id" :label="app.name" :value="app.id" />
          </ElSelect>
        </ElFormItem>
        <ElFormItem label="状态">
          <ElSelect v-model="searchForm.status" placeholder="全部" clearable style="width: 120px">
            <ElOption label="有效" value="active" />
            <ElOption label="已吊销" value="revoked" />
          </ElSelect>
        </ElFormItem>
        <ElFormItem>
          <ElButton type="primary" @click="handleSearch" v-ripple>搜索</ElButton>
          <ElButton @click="resetSearch">重置</ElButton>
        </ElFormItem>
      </ElForm>
    </div>

    <ElCard class="art-table-card" shadow="never">
      <ArtTableHeader v-model:columns="columnChecks" :loading="loading" @refresh="refreshData">
        <template #left>
          <ElSpace wrap>
            <ElButton type="primary" @click="openIssueDialog" v-ripple>生成授权文件</ElButton>
          </ElSpace>
        </template>
      </ArtTableHeader>

      <ArtTable
        :loading="loading"
        :data="data"
        :columns="columns"
        :pagination="pagination"
        @pagination:size-change="handleSizeChange"
        @pagination:current-change="handleCurrentChange"
      >
        <template #fileNo="{ row }">
          <span class="file-no">{{ row.fileNo }}</span>
          <div class="muted">{{ row.licenseNo }}</div>
        </template>

        <template #appName="{ row }">
          <div>{{ row.appName }}</div>
          <span class="muted">{{ row.planName || '无套餐' }}</span>
        </template>

        <template #bind="{ row }">
          <div class="bind-row">
            <ElTag v-for="item in row.domains" :key="`d-${item}`" size="small" type="success">
              域名 {{ item }}
            </ElTag>
            <ElTag v-for="item in row.ips" :key="`i-${item}`" size="small" type="warning">
              IP {{ item }}
            </ElTag>
            <ElTag v-for="item in row.machines" :key="`m-${item}`" size="small" type="info">
              机器码 {{ item }}
            </ElTag>
          </div>
        </template>

        <template #heartbeat="{ row }">
          <span>{{ row.heartbeatDays }} 天 / 宽限 {{ row.graceDays }} 天</span>
        </template>

        <template #lastSeenAt="{ row }">
          <div>{{ row.lastSeenAt || '未回源' }}</div>
          <span class="muted">{{ [row.lastDomain, row.lastMachine].filter(Boolean).join(' · ') }}</span>
        </template>

        <template #status="{ row }">
          <ElTag :type="row.status === 'active' ? 'success' : 'danger'" size="small">
            {{ row.status === 'active' ? '有效' : '已吊销' }}
          </ElTag>
        </template>

        <template #operation="{ row }">
          <ElButton link type="primary" @click="downloadFile(row)">下载</ElButton>
          <ElButton
            v-if="row.status === 'active'"
            link
            type="danger"
            @click="revokeFile(row)"
          >
            吊销
          </ElButton>
        </template>
      </ArtTable>
    </ElCard>

    <!-- 生成授权文件 -->
    <ElDialog v-model="issueDialog.visible" title="生成授权文件" width="620px" destroy-on-close>
      <ElAlert
        title="授权文件由服务端 RSA 私钥签名，SDK 使用公钥离线验签并按心跳周期回源。请至少绑定一种运行环境。"
        type="info"
        show-icon
        :closable="false"
        class="mb-16"
      />
      <ElForm ref="issueFormRef" :model="issueForm" :rules="issueRules" label-width="100px">
        <ElFormItem label="文件授权" prop="licenseId">
          <ElSelect
            v-model="issueForm.licenseId"
            placeholder="请选择类型为「文件授权」的授权"
            filterable
            remote
            clearable
            style="width: 100%"
            :remote-method="searchLicenses"
            :loading="licenseSearching"
            remote-show-suffix
          >
            <ElOption
              v-for="item in licenseOptions"
              :key="item.id"
              :label="`${item.licenseNo} · ${item.appName}`"
              :value="item.id"
            />
          </ElSelect>
        </ElFormItem>
        <ElFormItem label="绑定域名">
          <ElInput
            v-model="bindText.domains"
            type="textarea"
            :rows="2"
            placeholder="每行一个，留空表示不限制，支持 *.example.com 泛域名"
          />
        </ElFormItem>
        <ElFormItem label="绑定IP">
          <ElInput
            v-model="bindText.ips"
            type="textarea"
            :rows="2"
            placeholder="每行一个服务器 IP，留空表示不限制"
          />
        </ElFormItem>
        <ElFormItem label="机器码">
          <ElInput
            v-model="bindText.machines"
            type="textarea"
            :rows="2"
            placeholder="每行一个机器码（SDK 采集），留空表示不限制"
          />
        </ElFormItem>
        <ElSpace wrap>
          <ElFormItem label="心跳周期">
            <ElInputNumber v-model="issueForm.heartbeatDays" :min="0" :max="365" />
            <span class="form-tip">天，0 表示不做周期回源</span>
          </ElFormItem>
          <ElFormItem label="离线宽限">
            <ElInputNumber v-model="issueForm.graceDays" :min="0" :max="180" />
            <span class="form-tip">天，超出后离线校验失败</span>
          </ElFormItem>
        </ElSpace>
      </ElForm>
      <template #footer>
        <ElButton @click="issueDialog.visible = false">取消</ElButton>
        <ElButton type="primary" :loading="issueDialog.submitting" @click="submitIssue">
          生成并下载
        </ElButton>
      </template>
    </ElDialog>

    <!-- 生成结果 -->
    <ElDialog v-model="resultDialog.visible" title="授权文件已生成" width="720px" destroy-on-close>
      <ElAlert
        title="文件已自动下载。请连同公钥一并提供给客户，SDK 使用二者完成离线校验。"
        type="success"
        show-icon
        :closable="false"
        class="mb-16"
      />
      <ElForm label-width="100px">
        <ElFormItem label="文件编号">{{ resultDialog.fileNo }}</ElFormItem>
        <ElFormItem label="应用">{{ resultDialog.appName }}</ElFormItem>
        <ElFormItem label="公钥">
          <ElInput v-model="resultDialog.publicKey" type="textarea" :rows="4" readonly />
        </ElFormItem>
        <ElFormItem label="文件内容">
          <ElInput v-model="resultDialog.content" type="textarea" :rows="6" readonly />
        </ElFormItem>
      </ElForm>
      <template #footer>
        <ElButton @click="copyContent">复制文件内容</ElButton>
        <ElButton type="primary" @click="resultDialog.visible = false">完成</ElButton>
      </template>
    </ElDialog>
  </div>
</template>

<script setup lang="ts">
  import { ElMessage, ElMessageBox } from 'element-plus'
  import { useTable } from '@/hooks/core/useTable'
  import {
    fetchDownloadLicenseFile,
    fetchIssueLicenseFile,
    fetchLicenseAppList,
    fetchLicenseFileList,
    fetchLicenseList,
    fetchRevokeLicenseFile,
    type LicenseAppItem,
    type LicenseFileIssueParams,
    type LicenseFileItem,
    type LicenseFileSearchParams,
    type LicenseItem
  } from '@/api/license-manage'

  defineOptions({ name: 'LicenseFiles' })

  interface LicenseFileSearchForm {
    keyword?: string
    appId?: number
    status?: string
  }

  const searchForm = ref<LicenseFileSearchForm>({ keyword: undefined, appId: undefined, status: undefined })
  const appOptions = ref<LicenseAppItem[]>([])
  const licenseOptions = ref<LicenseItem[]>([])
  const licenseSearching = ref(false)

  const {
    columns,
    columnChecks,
    data,
    loading,
    pagination,
    getData,
    replaceSearchParams,
    handleSizeChange,
    handleCurrentChange,
    refreshData
  } = useTable({
    core: {
      apiFn: fetchLicenseFileList,
      apiParams: {
        page: 1,
        pageSize: 20,
        ...searchForm.value
      },
      paginationKey: { current: 'page', size: 'pageSize' },
      columnsFactory: () => [
        { prop: 'fileNo', label: '文件编号 / 授权编号', minWidth: 210, useSlot: true },
        { prop: 'appName', label: '应用 / 套餐', minWidth: 180, useSlot: true },
        { prop: 'bind', label: '运行环境绑定', minWidth: 260, useSlot: true },
        { prop: 'heartbeat', label: '心跳 / 宽限', width: 150, useSlot: true },
        { prop: 'lastSeenAt', label: '最近回源', width: 190, useSlot: true },
        { prop: 'status', label: '状态', width: 90, align: 'center', useSlot: true },
        { prop: 'createdAt', label: '签发时间', width: 160 },
        { prop: 'operation', label: '操作', width: 130, fixed: 'right', useSlot: true }
      ]
    },
    transform: {
      dataTransformer: (records) => (Array.isArray(records) ? records : [])
    }
  })

  const issueFormRef = ref()
  const issueDialog = reactive({ visible: false, submitting: false })
  const issueForm = reactive({
    licenseId: undefined as number | undefined,
    heartbeatDays: 30,
    graceDays: 7
  })
  const bindText = reactive({ domains: '', ips: '', machines: '' })
  const issueRules = {
    licenseId: [{ required: true, message: '请选择要签发的授权', trigger: 'change' }]
  }
  const resultDialog = reactive({
    visible: false,
    fileNo: '',
    appName: '',
    publicKey: '',
    content: ''
  })

  const splitLines = (value: string): string[] =>
    value
      .split('\n')
      .map((item) => item.trim())
      .filter((item) => item.length > 0)

  const handleSearch = () => {
    replaceSearchParams({ ...searchForm.value } as Partial<LicenseFileSearchParams>)
    getData()
  }

  const resetSearch = () => {
    searchForm.value = { keyword: undefined, appId: undefined, status: undefined }
    handleSearch()
  }

  /** 远程搜索文件授权类型的授权 */
  const searchLicenses = async (keyword: string) => {
    licenseSearching.value = true
    try {
      const res = await fetchLicenseList({
        page: 1,
        pageSize: 20,
        type: 'file',
        keyword: keyword || undefined
      })
      licenseOptions.value = res?.list || []
    } finally {
      licenseSearching.value = false
    }
  }

  const openIssueDialog = () => {
    issueForm.licenseId = undefined
    issueForm.heartbeatDays = 30
    issueForm.graceDays = 7
    bindText.domains = ''
    bindText.ips = ''
    bindText.machines = ''
    licenseOptions.value = []
    searchLicenses('')
    issueDialog.visible = true
  }

  const submitIssue = async () => {
    const valid = await issueFormRef.value?.validate().catch(() => false)
    if (!valid) return

    issueDialog.submitting = true
    try {
      const payload: LicenseFileIssueParams = {
        licenseId: issueForm.licenseId as number,
        domains: splitLines(bindText.domains),
        ips: splitLines(bindText.ips),
        machineIds: splitLines(bindText.machines),
        heartbeatDays: issueForm.heartbeatDays,
        graceDays: issueForm.graceDays
      }
      const result = await fetchIssueLicenseFile(payload)
      issueDialog.visible = false
      resultDialog.fileNo = result?.fileNo || ''
      resultDialog.appName = result?.appName || ''
      resultDialog.publicKey = result?.publicKey || ''
      resultDialog.content = result?.content || ''
      resultDialog.visible = true
      ElMessage.success('授权文件已生成')
      if (result?.content) {
        downloadText(result.content, `license-${result.fileNo}.lic`)
      }
      refreshData()
    } finally {
      issueDialog.submitting = false
    }
  }

  const downloadText = (content: string, fileName: string) => {
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = fileName
    link.click()
    URL.revokeObjectURL(url)
  }

  const downloadFile = async (row: LicenseFileItem) => {
    try {
      const blob = await fetchDownloadLicenseFile(row.id)
      const url = URL.createObjectURL(blob as Blob)
      const link = document.createElement('a')
      link.href = url
      link.download = `${row.fileNo}.lic`
      link.click()
      URL.revokeObjectURL(url)
    } catch {
      ElMessage.error('下载失败，请稍后重试')
    }
  }

  const copyContent = async () => {
    try {
      await navigator.clipboard.writeText(resultDialog.content)
      ElMessage.success('已复制文件内容')
    } catch {
      ElMessage.warning('浏览器拒绝了剪贴板访问，请手动复制')
    }
  }

  const revokeFile = async (row: LicenseFileItem) => {
    const { value } = await ElMessageBox.prompt(
      '吊销后客户端在下一次心跳回源时即会失效，请填写吊销原因。',
      `吊销 ${row.fileNo}`,
      { inputPlaceholder: '例如：客户申请退款', inputValidator: (v: string) => !!v?.trim() }
    ).catch(() => ({ value: '' }))
    if (!value) return
    await fetchRevokeLicenseFile(row.id, value.trim())
    ElMessage.success('授权文件已吊销')
    refreshData()
  }

  onMounted(async () => {
    appOptions.value = (await fetchLicenseAppList()) || []
  })
</script>

<style lang="scss" scoped>
  .license-files-page {
    .search-bar {
      margin-bottom: 16px;
    }

    .search-form {
      :deep(.el-form-item) {
        margin-bottom: 0;
      }
    }

    .file-no {
      font-family: var(--el-font-family-mono, monospace);
      font-weight: 600;
    }

    .muted {
      font-size: 12px;
      color: var(--art-gray-600);
    }

    .bind-row {
      display: flex;
      flex-wrap: wrap;
      gap: 4px;
    }

    .form-tip {
      margin-left: 8px;
      font-size: 12px;
      color: var(--art-gray-600);
    }
  }
</style>
