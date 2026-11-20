<#
.SYNOPSIS
    Shared Halo PSA / NinjaOne helpers used by every Invoke-*.ps1 monitor in this repo.

.DESCRIPTION
    Loaded at runtime by each script with Invoke-Expression, so the functions and
    variables below land in the calling script's scope. Fix a bug here once and every
    monitor gets it on its next run.

    Provides:
      - Get-NinjaConfig        read a Ninja custom field with a default
      - Get-HaloToken          client-credentials auth
      - Get-HaloClientSite     match this device to a Halo asset -> client, site AND asset id
      - New-HaloTicket         create a ticket (links the asset, retries transient failures)
      - Get-HaloTicketStatus / Close-HaloTicket / Add-HaloTicketNote

    Ninja custom fields read (System scope, Automation = Read):
        halopsaurl              Text    Halo base URL, e.g. https://yourtenant.halopsa.com
        halopsaclientid         Text    Halo API application (client credentials) ID
        halopsasecret           Secure  Halo API client secret
        halopsafallbackclientid Integer Halo client ID used when no asset match is found
        halopsafallbacksiteid   Integer Halo site ID used when no asset match is found
        halopsarmmcustomfieldid Integer Optional. Halo custom field ID set to 1 on created tickets
                                        (for example an "RMM selection" field). Omitted when blank.
        ninjadeviceid           Integer Optional. Improves asset matching (Scripts = Read).

    Callers may set $DebugLogging = $true before loading this file for verbose output.
#>

# -----------------------------------------------------------------------
# CONFIG
# -----------------------------------------------------------------------
function Get-NinjaConfig {
    param([string]$Name, $Default = "")
    # 2>$null: a missing field writes to the error stream (not catchable), which Ninja shows as noise
    try { $v = Ninja-Property-Get $Name 2>$null; if ($v) { return $v } } catch {}
    return $Default
}

$HaloBaseUrl      = (Get-NinjaConfig "halopsaurl" "https://yourtenant.halopsa.com").TrimEnd('/')
$HaloAuthUrl      = "$HaloBaseUrl/auth/token"
$HaloTenant       = ([uri]$HaloBaseUrl).Host.Split('.')[0]
$HaloClientId     = Get-NinjaConfig "halopsaclientid" ""
try { $HaloClientSecret = Ninja-Property-Get halopsasecret 2>$null } catch { $HaloClientSecret = "" }
$FallbackClientId = [int](Get-NinjaConfig "halopsafallbackclientid" 0)
$FallbackSiteId   = [int](Get-NinjaConfig "halopsafallbacksiteid" 0)
$HaloRmmFieldId   = [int](Get-NinjaConfig "halopsarmmcustomfieldid" 0)

if ($null -eq $DebugLogging) { $DebugLogging = $false }

if ($FallbackClientId -le 0 -or $FallbackSiteId -le 0) {
    Write-Host "WARNING: halopsafallbackclientid / halopsafallbacksiteid are not set. Devices with no matching Halo asset will NOT get a ticket."
}

# -----------------------------------------------------------------------
# HELPERS
# -----------------------------------------------------------------------
function Write-DebugLog {
    param([string]$Message)
    if ($DebugLogging) { Write-Host "[DEBUG $(Get-Date -Format 'HH:mm:ss')] $Message" }
}

function Get-HttpErrorBody {
    param($ErrorRecord)
    $body = $null
    try { $body = $ErrorRecord.ErrorDetails.Message } catch {}
    if (-not $body) {
        try {
            $stream = $ErrorRecord.Exception.Response.GetResponseStream()
            $body   = (New-Object System.IO.StreamReader($stream)).ReadToEnd()
        } catch {}
    }
    return $body
}

# -----------------------------------------------------------------------
# HALO FUNCTIONS
# -----------------------------------------------------------------------
function Get-HaloToken {
    try {
        $response = Invoke-RestMethod `
            -Uri         $HaloAuthUrl `
            -Method      POST `
            -Headers     @{ "halo-tenant" = $HaloTenant } `
            -Body        @{
                grant_type    = "client_credentials"
                client_id     = $HaloClientId
                client_secret = $HaloClientSecret
                scope         = "read:tickets edit:tickets read:customers read:assets"
            } `
            -ContentType "application/x-www-form-urlencoded" `
            -ErrorAction Stop
        return $response.access_token
    } catch {
        Write-Host "WARNING: Halo auth failed - $($_.Exception.Message)"
        return $null
    }
}

function Get-NinjaDeviceId {
    # Sources tried in order: optional Ninja custom field, then NINJA* environment variables.
    # Returns "" if none found.
    $envMatches = Get-ChildItem Env: -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'ninja' }
    foreach ($e in $envMatches) { Write-DebugLog "  env: $($e.Name)=$($e.Value)" }

    try { $fromField = Ninja-Property-Get ninjadeviceid 2>$null } catch { $fromField = "" }
    if ($fromField -and "$fromField".Trim() -match '^\d+$') {
        Write-DebugLog "Ninja device ID from custom field ninjadeviceid: $fromField"
        return "$fromField".Trim()
    }
    foreach ($name in @('NINJA_DEVICE_ID','NINJA_NODE_ID','NINJA_DEVICEID','NINJA_NODEID')) {
        $v = [Environment]::GetEnvironmentVariable($name)
        if ($v -and $v -match '^\d+$') {
            Write-DebugLog "Ninja device ID from env $name`: $v"
            return $v
        }
    }
    Write-DebugLog "No Ninja device ID available (no ninjadeviceid field value, no matching env var) - hostname matching only."
    return ""
}

function Get-HaloClientSite {
    # Returns @{ ClientId; SiteId; AssetId; Source; IsFallback; FallbackReason }.
    # AssetId is $null when the device could not be matched to exactly one Halo asset.
    param([string]$Token)
    $fallback = @{ ClientId = $FallbackClientId; SiteId = $FallbackSiteId; AssetId = $null; Source = "fallback (default client)"; IsFallback = $true; FallbackReason = "no matching Halo asset found" }
    if (-not $Token) { $fallback.FallbackReason = "no Halo token"; return $fallback }
    try {
        $ninjaId = Get-NinjaDeviceId
        $uri = "$HaloBaseUrl/api/asset?search=$env:COMPUTERNAME&count=50"
        Write-DebugLog "Asset lookup: GET $uri (ninja device id: '$ninjaId')"
        $results = Invoke-RestMethod `
            -Uri     $uri `
            -Headers @{ "Authorization" = "Bearer $Token" } `
            -ErrorAction Stop
        $candidates = @($results.assets)
        Write-DebugLog "Asset lookup returned $($candidates.Count) candidate(s) (record_count: $($results.record_count))"
        if ($results.record_count -gt $candidates.Count) {
            Write-Host "WARNING: Halo has more matches ($($results.record_count)) than were returned ($($candidates.Count)) - the right asset may be missing from this page."
        }
        foreach ($a in $candidates) {
            Write-DebugLog "  candidate: id=$($a.id) inventory_number='$($a.inventory_number)' ninjarmm_id='$($a.ninjarmm_id)' name='$($a.name)' client='$($a.client_name)' site='$($a.site_name)' client_id=$($a.client_id) site_id=$($a.site_id)"
        }

        $asset = $null
        $method = ""

        # 1) Match on Ninja device ID (unique per device, survives renames)
        if ($ninjaId) {
            $byId = @($candidates | Where-Object { "$($_.ninjarmm_id)" -eq $ninjaId })
            if ($byId.Count -eq 1) {
                $asset = $byId[0]; $method = "ninjarmm_id"
                Write-DebugLog "Matched asset id=$($asset.id) on ninjarmm_id '$ninjaId'"
            } elseif ($byId.Count -gt 1) {
                Write-Host "WARNING: $($byId.Count) Halo assets share ninjarmm_id '$ninjaId' (ids: $(($byId | ForEach-Object { $_.id }) -join ', ')) - not linking an asset."
                $fallback.FallbackReason = "multiple Halo assets share this Ninja device ID"
                return $fallback
            } else {
                Write-DebugLog "No candidate had ninjarmm_id '$ninjaId' - falling back to hostname match."
            }
        }

        # 2) Match on hostname (inventory_number), with duplicate guard
        if (-not $asset) {
            $byName = @($candidates | Where-Object { $_.inventory_number -eq $env:COMPUTERNAME })
            if ($byName.Count -eq 1) {
                $asset = $byName[0]; $method = "hostname"
                # Guard: the hostname match belongs to a different Ninja device
                if ($ninjaId -and $asset.ninjarmm_id -and "$($asset.ninjarmm_id)" -ne $ninjaId) {
                    Write-Host "WARNING: Halo asset $($asset.id) matches hostname but has ninjarmm_id '$($asset.ninjarmm_id)' (this device is '$ninjaId') - not linking an asset."
                    $fallback.FallbackReason = "hostname matched an asset belonging to a different Ninja device"
                    return $fallback
                }
                Write-DebugLog "Matched asset id=$($asset.id) on inventory_number '$env:COMPUTERNAME'"
            } elseif ($byName.Count -gt 1) {
                Write-Host "WARNING: $($byName.Count) Halo assets match hostname '$env:COMPUTERNAME' (ids: $(($byName | ForEach-Object { $_.id }) -join ', '); clients: $(($byName | ForEach-Object { $_.client_name }) -join ' | ')) - ambiguous, not linking an asset."
                $fallback.FallbackReason = "hostname matches $($byName.Count) Halo assets (ambiguous)"
                return $fallback
            } else {
                Write-DebugLog "No candidate had inventory_number equal to '$env:COMPUTERNAME'"
            }
        }

        if ($asset -and $asset.client_id -and $asset.site_id) {
            return @{ ClientId = $asset.client_id; SiteId = $asset.site_id; AssetId = $asset.id; Source = "Halo asset ($($asset.client_name) / $($asset.site_name)) [matched by $method]"; IsFallback = $false; FallbackReason = $null }
        }
    } catch {
        Write-Host "WARNING: Asset lookup failed - $($_.Exception.Message). Using fallback."
        $fallback.FallbackReason = "asset lookup failed"
    }
    return $fallback
}

function New-HaloTicket {
    param(
        [string]$Token,
        [int]$ClientId,
        [int]$SiteId,
        [string]$Summary,
        [string]$Details,
        [int]$TicketType,
        [int]$Priority = 3,
        [int]$Status   = 1,
        [int]$Urgency  = 2,
        [int]$AssetId  = 0
    )
    if (-not $Token) { Write-Host "WARNING: No Halo token, skipping ticket creation."; return $null }
    if ($ClientId -le 0 -or $SiteId -le 0) {
        Write-Host "WARNING: No Halo client/site for this device (no asset match and no fallback configured) - skipping ticket creation. Set halopsafallbackclientid and halopsafallbacksiteid."
        return $null
    }

    $ticket = @{
        summary       = $Summary
        details_html  = $Details
        tickettype_id = $TicketType
        client_id     = $ClientId
        site_id       = $SiteId
        category_1    = $HaloCategoryId
        impact        = $HaloImpactId
        urgency       = $Urgency
        priority_id   = $Priority
        status_id     = $Status
    }
    if ($HaloRmmFieldId -gt 0) { $ticket.customfields = @(@{ id = $HaloRmmFieldId; value = 1 }) }
    if ($AssetId -gt 0)        { $ticket.assets       = @(@{ id = $AssetId }) }
    $body = "[" + ($ticket | ConvertTo-Json -Depth 5) + "]"

    Write-DebugLog "New-HaloTicket: AssetId = $AssetId (type $TicketType, client $ClientId, site $SiteId)"
    $debugTicket = $ticket.Clone(); $debugTicket.details_html = "<omitted, $($Details.Length) chars>"
    Write-DebugLog ("request body: [" + ($debugTicket | ConvertTo-Json -Depth 5 -Compress) + "]")

    # Retry on transient failures only: HTTP 5xx, 429, or no response (network).
    # 4xx (e.g. malformed payload) is not retried - resending won't help.
    $maxAttempts = 3
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            $r = Invoke-WebRequest -UseBasicParsing `
                -Uri     "$HaloBaseUrl/api/tickets" `
                -Method  POST `
                -Headers @{ "Authorization" = "Bearer $Token"; "Content-Type" = "application/json" } `
                -Body    $body `
                -ErrorAction Stop

            if ($r.StatusCode -in 200, 201) {
                $created = $r.Content | ConvertFrom-Json
                $newId = $created[0].id
                Write-Host "Halo ticket created: #$newId - $($created[0].summary)"
                if ($AssetId -gt 0) {
                    $linked = @($created[0].assets)
                    Write-DebugLog "Assets on created ticket response: $(if ($linked.Count -gt 0 -and $linked[0]) { ($linked | ForEach-Object { $_.id }) -join ',' } else { '(none returned in POST response)' })"
                    if ($DebugLogging) {
                        try {
                            $check = Invoke-RestMethod `
                                -Uri     "$HaloBaseUrl/api/tickets/${newId}?includedetails=true" `
                                -Headers @{ "Authorization" = "Bearer $Token" } `
                                -ErrorAction Stop
                            Write-DebugLog "Verify GET ticket #${newId}: asset_id=$($check.asset_id) assets=$(if ($check.assets) { ($check.assets | ForEach-Object { $_.id }) -join ',' } else { '(none)' })"
                        } catch {
                            Write-DebugLog "Verify GET failed: $($_.Exception.Message)"
                        }
                    }
                }
                return $newId
            }
            Write-Host "WARNING: Halo ticket creation failed - $($r.Content)"
            return $null
        } catch {
            $code      = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { $null }
            $retryable = (-not $code) -or ($code -ge 500) -or ($code -eq 429)
            if ($retryable -and $attempt -lt $maxAttempts) {
                $delay = 5 * $attempt   # 5s, then 10s
                Write-Host "WARNING: Ticket creation attempt $attempt/$maxAttempts failed (HTTP $code) - retrying in ${delay}s: $($_.Exception.Message)"
                Start-Sleep -Seconds $delay
                continue
            }
            Write-Host "WARNING: Halo ticket creation failed after $attempt attempt(s) (HTTP $code) - $($_.Exception.Message)"
            Write-DebugLog "error response body: $(Get-HttpErrorBody $_)"
            return $null
        }
    }
    return $null
}

function Get-HaloTicketStatus {
    param([string]$Token, [string]$TicketId)
    if (-not $Token -or -not $TicketId) { return $null }
    try {
        $r = Invoke-RestMethod `
            -Uri     "$HaloBaseUrl/api/tickets/$TicketId" `
            -Headers @{ "Authorization" = "Bearer $Token" } `
            -ErrorAction Stop
        return $r.status_id
    } catch {
        Write-Host "WARNING: Could not query ticket #$TicketId - $($_.Exception.Message)"
        return $null
    }
}

function Close-HaloTicket {
    param([string]$Token, [string]$TicketId)
    if (-not $Token) { Write-Host "WARNING: No Halo token, skipping ticket close."; return }
    $body = "[" + (@{ id = [int]$TicketId; status_id = 9 } | ConvertTo-Json -Depth 3) + "]"
    try {
        $r = Invoke-WebRequest -UseBasicParsing `
            -Uri     "$HaloBaseUrl/api/tickets" `
            -Method  POST `
            -Headers @{ "Authorization" = "Bearer $Token"; "Content-Type" = "application/json" } `
            -Body    $body `
            -ErrorAction SilentlyContinue
        if ($r.StatusCode -in 200, 201) {
            Write-Host "Halo ticket #$TicketId closed."
        } else {
            Write-Host "WARNING: Could not close ticket #$TicketId - $($r.Content)"
        }
    } catch {
        Write-Host "WARNING: Could not close ticket #$TicketId - $($_.Exception.Message)"
    }
}

function Add-HaloTicketNote {
    param([string]$Token, [string]$TicketId, [string]$Note)
    if (-not $Token) { Write-Host "WARNING: No Halo token, skipping note."; return }
    $action = @{
        ticket_id        = [int]$TicketId
        note             = $Note
        hiddenfromclient = $true
        outcome          = "none"
    }
    $body = "[" + ($action | ConvertTo-Json -Depth 5) + "]"
    try {
        $r = Invoke-WebRequest -UseBasicParsing `
            -Uri     "$HaloBaseUrl/api/actions" `
            -Method  POST `
            -Headers @{ "Authorization" = "Bearer $Token"; "Content-Type" = "application/json" } `
            -Body    $body `
            -ErrorAction SilentlyContinue
        if ($r.StatusCode -in 200, 201) {
            Write-Host "Note added to Halo ticket #$TicketId"
        } else {
            Write-Host "WARNING: Could not add note to ticket #$TicketId - $($r.Content)"
        }
    } catch {
        Write-Host "WARNING: Could not add note to ticket #$TicketId - $($_.Exception.Message)"
    }
}
