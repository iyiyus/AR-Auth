#Requires -Version 7.0

param(
  [Parameter(Mandatory = $true)]
  [string]$Version,
  [string]$Repository = 'iyiyus/AR-Auth',
  [string]$Remote = 'origin',
  [switch]$SkipTests
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($Version -notmatch '^\d+\.\d+\.\d+$') {
  throw "Version must match X.Y.Z: $Version"
}
if ($Repository -notmatch '^([^/]+)/([^/]+)$') {
  throw "Repository must match owner/repo: $Repository"
}

$AccessToken = $env:GH_TOKEN
if ([string]::IsNullOrWhiteSpace($AccessToken)) { $AccessToken = $env:GITHUB_TOKEN }
if ([string]::IsNullOrWhiteSpace($AccessToken)) {
  throw 'GH_TOKEN (or GITHUB_TOKEN) is required'
}

$Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$Owner = $Matches[1]
$Repo = $Matches[2]
$Tag = "v$Version"
$ApiBase = "https://api.github.com/repos/$Owner/$Repo"
$UploadsBase = "https://uploads.github.com/repos/$Owner/$Repo"
$PackagesDir = Join-Path $Root 'release/packages'
$PackagePath = Join-Path $PackagesDir "auth_pro-full-v$Version.tar.gz"
$LatestPath = Join-Path $PackagesDir 'latest.json'
$ReleasesPath = Join-Path $PackagesDir 'releases.json'

$AuthHeaders = @{
  Authorization = "Bearer $AccessToken"
  Accept        = 'application/vnd.github+json'
  'User-Agent'  = 'auth-pro-release-publisher'
}

function Invoke-Git {
  param([Parameter(Mandatory = $true)][string[]]$Arguments)

  $output = & git @Arguments 2>&1
  if ($LASTEXITCODE -ne 0) {
    throw "git $($Arguments -join ' ') failed: $($output -join [Environment]::NewLine)"
  }
  return ($output -join [Environment]::NewLine).Trim()
}

function Get-GitHubRelease {
  param([Parameter(Mandatory = $true)][string]$Uri)

  try {
    return Invoke-RestMethod -Uri $Uri -Method Get -Headers $AuthHeaders
  } catch {
    if ($null -ne $_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 404) {
      return $null
    }
    throw
  }
}

Push-Location $Root
try {
  $status = Invoke-Git @('status', '--porcelain')
  if ($status) {
    throw 'Working tree must be clean before publishing a release'
  }

  $remoteUrl = Invoke-Git @('remote', 'get-url', $Remote)
  if ($remoteUrl -notmatch "(?i)github\.com[/:]$([Regex]::Escape($Owner))/$([Regex]::Escape($Repo))(?:\.git)?$") {
    throw "Remote $Remote does not point to https://github.com/${Repository}: $remoteUrl"
  }

  $headCommit = Invoke-Git @('rev-parse', 'HEAD')
  $tagCommit = Invoke-Git @('rev-list', '-n', '1', $Tag)
  if ($headCommit -ne $tagCommit) {
    throw "Tag $Tag must point to HEAD before publishing"
  }
  Invoke-Git @('ls-remote', '--exit-code', '--tags', $Remote, "refs/tags/$Tag") | Out-Null

  $existingRelease = Get-GitHubRelease "$ApiBase/releases/tags/$Tag"
  if ($null -ne $existingRelease) {
    throw "GitHub Release $Tag already exists"
  }

  New-Item -ItemType Directory -Force -Path $PackagesDir | Out-Null
  $latestRelease = Get-GitHubRelease "$ApiBase/releases/latest"
  if ($null -ne $latestRelease) {
    $historyAsset = $latestRelease.assets | Where-Object { $_.name -eq 'releases.json' } | Select-Object -First 1
    if ($null -ne $historyAsset) {
      Invoke-WebRequest -Uri $historyAsset.browser_download_url -Headers $AuthHeaders -OutFile $ReleasesPath
    } else {
      Remove-Item -LiteralPath $ReleasesPath -Force -ErrorAction SilentlyContinue
    }
  } else {
    Remove-Item -LiteralPath $ReleasesPath -Force -ErrorAction SilentlyContinue
  }

  $environmentNames = @(
    'AUTO_PRO_RELEASE_REPOSITORY',
    'AUTO_PRO_UPDATE_PACKAGE_BASE_URL',
    'AUTO_PRO_UPDATE_RELEASES_URL',
    'AUTO_PRO_REQUIRE_GIT_RELEASE_NOTES',
    'AUTO_PRO_RELEASE_CURRENT_REF'
  )
  $previousEnvironment = @{}
  foreach ($name in $environmentNames) {
    $previousEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
  }
  try {
    $downloadBase = "https://github.com/$Repository/releases/download/$Tag"
    $env:AUTO_PRO_RELEASE_REPOSITORY = $Repository
    $env:AUTO_PRO_UPDATE_PACKAGE_BASE_URL = $downloadBase
    $env:AUTO_PRO_UPDATE_RELEASES_URL = "$downloadBase/releases.json"
    $env:AUTO_PRO_REQUIRE_GIT_RELEASE_NOTES = '1'
    $env:AUTO_PRO_RELEASE_CURRENT_REF = $Tag
    & (Join-Path $PSScriptRoot 'build-release.ps1') -Version $Version
    if ($LASTEXITCODE -ne 0) {
      throw 'Release build failed'
    }
  } finally {
    foreach ($name in $environmentNames) {
      [Environment]::SetEnvironmentVariable($name, $previousEnvironment[$name], 'Process')
    }
  }

  foreach ($path in @($PackagePath, $LatestPath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf) -or (Get-Item -LiteralPath $path).Length -eq 0) {
      throw "Release asset was not generated: $path"
    }
  }

  if (-not $SkipTests) {
    Write-Host '[verify] Running backend tests...'
    & go -C (Join-Path $Root 'backend') test ./...
    if ($LASTEXITCODE -ne 0) {
      throw 'Backend tests failed'
    }
  }

  $manifest = Get-Content -LiteralPath $LatestPath -Raw | ConvertFrom-Json
  $releaseBody = ($manifest.notes | ForEach-Object { "- $_" }) -join [Environment]::NewLine
  if ([string]::IsNullOrWhiteSpace($releaseBody)) {
    $releaseBody = "Version $Version"
  }

  Write-Host "Creating GitHub Release $Tag..."
  $release = Invoke-RestMethod -Uri "$ApiBase/releases" -Method Post -Headers $AuthHeaders -Body (@{
      tag_name         = $Tag
      name             = $Tag
      body             = $releaseBody
      prerelease       = $false
      target_commitish = $headCommit
    } | ConvertTo-Json)

  try {
    $assets = @($PackagePath, $LatestPath)
    # 历史版本清单由上一个 Release 合并而来，存在时一并上传
    if (Test-Path -LiteralPath $ReleasesPath -PathType Leaf) {
      $assets += $ReleasesPath
    }
    foreach ($path in $assets) {
      $name = Split-Path -Leaf $path
      Write-Host "Uploading $name..."
      $encodedName = [Uri]::EscapeDataString($name)
      Invoke-RestMethod -Uri "$UploadsBase/releases/$($release.id)/assets?name=$encodedName" -Method Post -Headers ($AuthHeaders + @{ 'Content-Type' = 'application/octet-stream' }) -Body ([System.IO.File]::ReadAllBytes($path)) | Out-Null
    }
  } catch {
    $publishError = $_
    try {
      Invoke-RestMethod -Uri "$ApiBase/releases/$($release.id)" -Method Delete -Headers $AuthHeaders | Out-Null
    } catch {
      Write-Warning "Failed to remove incomplete GitHub Release $Tag"
    }
    throw $publishError
  }

  Write-Host "Published: https://github.com/$Repository/releases/tag/$Tag"
} finally {
  Pop-Location
}
