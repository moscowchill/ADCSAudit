<#
.SYNOPSIS
    Offline-quality AD CS (ADCS) ESC audit, run live from a domain-joined management server.

.DESCRIPTION
    Enumerates certificate templates and Enterprise CAs straight from the AD Configuration
    partition and the CAs themselves, then flags the standard Certipy/Certify "ESC"
    misconfigurations:

        Template-side : ESC1, ESC2, ESC3, ESC4, ESC9, ESC13, ESC15
        CA-side       : ESC6, ESC7, ESC8, ESC11, ESC16
        DC-side       : ESC10 (weak certificate mapping)

    No RSAT / ActiveDirectory module required - uses System.DirectoryServices + certutil only,
    so it runs on any domain-joined Windows box. SIDs are resolved live and broad/low-privileged
    enrollment is detected (including nested group membership), which is exactly what an offline
    template-cache export cannot tell you.

.PARAMETER OutputDir
    Folder for the report files (.txt/.csv/.json). Default: .\ADCSAudit_<timestamp>

.PARAMETER SkipCAConfig
    Skip the certutil queries against each CA (ESC6/7/11/16). Use if CAs are unreachable.

.PARAMETER SkipWebEnrollment
    Skip the HTTP(S) probes of /certsrv (ESC8). Use to stay quiet on the network.

.PARAMETER SkipDCChecks
    Skip the remote-registry ESC10 check against domain controllers.

.PARAMETER VulnerableOnly
    Only print templates/CAs that have at least one finding.

.EXAMPLE
    .\Invoke-ADCSAudit.ps1

.EXAMPLE
    .\Invoke-ADCSAudit.ps1 -VulnerableOnly -SkipWebEnrollment

.NOTES
    Authorized assessment use only. Read-only: it makes no changes to AD or the CAs.
#>
[CmdletBinding()]
param(
    [string]$OutputDir,
    [switch]$SkipCAConfig,
    [switch]$SkipWebEnrollment,
    [switch]$SkipDCChecks,
    [switch]$VulnerableOnly
)

$ErrorActionPreference = 'Stop'
$script:Stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
if (-not $OutputDir) { $OutputDir = Join-Path (Get-Location) "ADCSAudit_$script:Stamp" }
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
$GUID_Enroll      = [Guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55'
$GUID_AutoEnroll  = [Guid]'a05b8cc2-17bc-4802-a710-e7c15ab866a2'
$GUID_All         = [Guid]'00000000-0000-0000-0000-000000000000'

# msPKI-Certificate-Name-Flag
$ENROLLEE_SUPPLIES_SUBJECT          = 0x00000001
$ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME = 0x00010000
# msPKI-Enrollment-Flag
$PEND_ALL_REQUESTS    = 0x00000002   # manager approval
$NO_SECURITY_EXTENSION = 0x00080000  # ESC9
# CA EditFlags / InterfaceFlags / disabled extension
$EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00040000  # ESC6
$IF_ENFORCEENCRYPTICERTREQUEST  = 0x00000200  # ESC11 (absence)
$OID_SECURITY_EXT = '1.3.6.1.4.1.311.25.2'     # ESC16 (if disabled)

$EKU_ClientAuth   = '1.3.6.1.5.5.7.3.2'
$EKU_SmartCard    = '1.3.6.1.4.1.311.20.2.2'
$EKU_PKINIT       = '1.3.6.1.5.2.3.4'
$EKU_AnyPurpose   = '2.5.29.37.0'
$EKU_CertReqAgent = '1.3.6.1.4.1.311.20.2.1'

# CA security access mask bits (ICertAdmin)
$CA_MANAGE_CA   = 1
$CA_MANAGE_CERT = 2
$CA_ENROLL      = 0x200

$script:Findings = New-Object System.Collections.Generic.List[object]
$script:SidNameCache = @{}
$script:CAEsc6 = @{}        # CA name -> $true if EDITF_ATTRIBUTESUBJECTALTNAME2 enabled
$script:TemplateCAs = @{}   # template name -> list of CAs that publish it

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
function Write-Head($t) { Write-Host ""; Write-Host ("=" * 78) -ForegroundColor DarkGray; Write-Host $t -ForegroundColor Cyan; Write-Host ("=" * 78) -ForegroundColor DarkGray }
function Write-Vuln($id,$msg) { Write-Host ("    [!] {0,-6} {1}" -f $id,$msg) -ForegroundColor Red }
function Write-Info($msg)     { Write-Host "[*] $msg" -ForegroundColor Gray }
function Write-Ok($msg)       { Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Warn2($msg)    { Write-Host "[-] $msg" -ForegroundColor Yellow }

function Add-Finding($Type,$Name,$ESC,$Severity,$Detail,$Principals) {
    $script:Findings.Add([pscustomobject]@{
        ObjectType = $Type; Object = $Name; ESC = $ESC; Severity = $Severity
        Detail = $Detail; Principals = ($Principals -join '; ')
    })
}

# ---------------------------------------------------------------------------
# LDAP plumbing (no RSAT)
# ---------------------------------------------------------------------------
function Get-RootDSE { [ADSI]'LDAP://RootDSE' }

function New-Searcher($BaseDN,$Filter,$Props,[switch]$WithSD) {
    $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$BaseDN")
    $ds = New-Object System.DirectoryServices.DirectorySearcher($entry)
    $ds.Filter = $Filter
    $ds.PageSize = 1000
    $ds.SecurityMasks = [System.DirectoryServices.SecurityMasks]'Dacl,Owner,Group'
    foreach ($p in $Props) { [void]$ds.PropertiesToLoad.Add($p) }
    return $ds
}

function Resolve-Sid([string]$Sid) {
    if ($script:SidNameCache.ContainsKey($Sid)) { return $script:SidNameCache[$Sid] }
    $name = $Sid
    try { $name = (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value } catch {}
    $script:SidNameCache[$Sid] = $name
    return $name
}

# ---------------------------------------------------------------------------
# Threat-model: which principals count as "low privileged / broadly reachable"
# ---------------------------------------------------------------------------
function Initialize-ThreatModel($ConfigNC) {
    $rootDSE = Get-RootDSE
    $domainNC = $rootDSE.defaultNamingContext[0]
    $domObj = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$domainNC")
    $domSidBytes = $domObj.Properties['objectSid'][0]
    $script:DomainSid = (New-Object System.Security.Principal.SecurityIdentifier($domSidBytes,0)).Value
    $script:DomainNC = $domainNC

    $script:BroadSids = @(
        'S-1-1-0'          # Everyone
        'S-1-5-7'          # Anonymous
        'S-1-5-11'         # Authenticated Users
        'S-1-5-32-545'     # BUILTIN\Users
        "$script:DomainSid-513"  # Domain Users
        "$script:DomainSid-514"  # Domain Guests
        "$script:DomainSid-515"  # Domain Computers
    )
    Write-Info "Domain SID: $script:DomainSid"
    Write-Info ("Low-priv principals: " + ($script:BroadSids -join ', '))
}

# Returns $true if a SID is broadly reachable by a low-priv user
# (directly a broad SID, or a group that transitively contains Domain Users/Computers)
$script:LowPrivCache = @{}
function Test-LowPriv([string]$Sid) {
    if ($script:BroadSids -contains $Sid) { return $true }
    if ($script:LowPrivCache.ContainsKey($Sid)) { return $script:LowPrivCache[$Sid] }
    $result = $false
    # Nested check: does this group (transitively) contain Domain Users or Domain Computers?
    try {
        $grp = New-Searcher $script:DomainNC "(objectSid=$Sid)" @('distinguishedName','objectClass')
        $g = $grp.FindOne()
        if ($g -and ($g.Properties['objectclass'] -contains 'group')) {
            $gdn = $g.Properties['distinguishedname'][0]
            $du = "$script:DomainSid-513"; $dc = "$script:DomainSid-515"
            $f = "(&(|(objectSid=$du)(objectSid=$dc))(memberOf:1.2.840.113556.1.4.1941:=$gdn))"
            $chk = New-Searcher $script:DomainNC $f @('objectSid')
            if ($chk.FindOne()) { $result = $true }
        }
    } catch {}
    $script:LowPrivCache[$Sid] = $result
    return $result
}

# ---------------------------------------------------------------------------
# Parse a template's nTSecurityDescriptor -> enroll / control principals
# ---------------------------------------------------------------------------
function Get-TemplateRights($sdBytes) {
    $sec = New-Object System.DirectoryServices.ActiveDirectorySecurity
    $sec.SetSecurityDescriptorBinaryForm($sdBytes)
    $ownerSid = $sec.GetOwner([System.Security.Principal.SecurityIdentifier]).Value

    $enroll = New-Object System.Collections.Generic.List[string]
    $control = New-Object System.Collections.Generic.List[string]   # WriteDacl/WriteOwner/GenericAll/GenericWrite/WriteProperty(all)

    $rules = $sec.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
    foreach ($r in $rules) {
        if ($r.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
        $sid = $r.IdentityReference.Value
        $rights = $r.ActiveDirectoryRights
        $ot = $r.ObjectType

        # NB: GenericAll/GenericWrite are COMPOSITE flags (they include ReadControl etc.),
        # so a plain -band gives false positives for any principal that merely has Read.
        # HasFlag() requires ALL bits of the composite to be present - which is correct.
        $hasExt   = $rights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight)
        $genAll   = $rights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::GenericAll)
        if ($genAll -or ($hasExt -and ($ot -eq $GUID_Enroll -or $ot -eq $GUID_All))) {
            $enroll.Add($sid)
        }
        $genWrite = $rights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::GenericWrite)
        $wDacl    = $rights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::WriteDacl)
        $wOwner   = $rights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::WriteOwner)
        $wProp    = $rights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::WriteProperty)
        if ($genAll -or $genWrite -or $wDacl -or $wOwner -or ($wProp -and $ot -eq $GUID_All)) {
            $control.Add($sid)
        }
    }
    return [pscustomobject]@{
        Owner   = $ownerSid
        Enroll  = ($enroll | Select-Object -Unique)
        Control = ($control | Select-Object -Unique)
    }
}

# ---------------------------------------------------------------------------
# Template enumeration + ESC checks
# ---------------------------------------------------------------------------
function Invoke-TemplateAudit($ConfigNC,$PublishedMap,$OidGroupLinks) {
    Write-Head "CERTIFICATE TEMPLATES"
    $base = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigNC"
    $props = @('name','displayName','msPKI-Certificate-Name-Flag','msPKI-Enrollment-Flag',
               'msPKI-RA-Signature','msPKI-Template-Schema-Version','pKIExtendedKeyUsage',
               'msPKI-Certificate-Policy','msPKI-Certificate-Application-Policy','nTSecurityDescriptor')
    $ds = New-Searcher $base '(objectClass=pKICertificateTemplate)' $props
    $results = $ds.FindAll()

    $report = New-Object System.Collections.Generic.List[object]

    foreach ($t in $results) {
        $p = $t.Properties
        $name = [string]$p['name'][0]
        $display = if ($p['displayname'].Count) { [string]$p['displayname'][0] } else { $name }
        $nameFlag = if ($p['mspki-certificate-name-flag'].Count) { [int]$p['mspki-certificate-name-flag'][0] } else { 0 }
        $enrFlag  = if ($p['mspki-enrollment-flag'].Count) { [int]$p['mspki-enrollment-flag'][0] } else { 0 }
        $raSig    = if ($p['mspki-ra-signature'].Count) { [int]$p['mspki-ra-signature'][0] } else { 0 }
        $schema   = if ($p['mspki-template-schema-version'].Count) { [int]$p['mspki-template-schema-version'][0] } else { 1 }
        $ekus = @(); foreach ($e in $p['pkiextendedkeyusage']) { $ekus += [string]$e }
        $policies = @(); foreach ($pol in $p['mspki-certificate-policy']) { $policies += [string]$pol }

        $ess = ($nameFlag -band $ENROLLEE_SUPPLIES_SUBJECT) -ne 0
        $mgrApproval = ($enrFlag -band $PEND_ALL_REQUESTS) -ne 0
        $noSecExt = ($enrFlag -band $NO_SECURITY_EXTENSION) -ne 0
        $anyPurpose = ($ekus.Count -eq 0) -or ($ekus -contains $EKU_AnyPurpose)
        $clientAuth = $anyPurpose -or ($ekus -contains $EKU_ClientAuth) -or ($ekus -contains $EKU_SmartCard) -or ($ekus -contains $EKU_PKINIT)
        $enrollAgent = $anyPurpose -or ($ekus -contains $EKU_CertReqAgent)
        $published = $PublishedMap.ContainsKey($name)

        $rights = Get-TemplateRights ($p['ntsecuritydescriptor'][0])
        $lowEnroll  = @($rights.Enroll  | Where-Object { Test-LowPriv $_ })
        $lowControl = @($rights.Control | Where-Object { Test-LowPriv $_ })
        $ownerLow = Test-LowPriv $rights.Owner
        $ownerDefault = ($rights.Owner -match '-(500|512|518|519)$') -or ($rights.Owner -in @('S-1-5-18','S-1-5-32-544','S-1-5-9'))

        $enrollNames  = @($rights.Enroll  | ForEach-Object { Resolve-Sid $_ })
        $lowEnrollNames= @($lowEnroll | ForEach-Object { Resolve-Sid $_ })
        $lowCtrlNames = @($lowControl | ForEach-Object { Resolve-Sid $_ })

        $vulns = @()
        $approvalGated = $mgrApproval -or ($raSig -gt 0)

        if ($published -and $lowEnroll.Count -and -not $approvalGated) {
            # ESC6 amplification: if the issuing CA has EDITF_ATTRIBUTESUBJECTALTNAME2, ANY
            # client-auth template - even without enrollee-supplies-subject - is effectively
            # ESC1: the requester injects an arbitrary SAN (e.g. a DA UPN) at request time.
            if ($clientAuth) {
                $esc6cas = @(); foreach ($caN in @($script:TemplateCAs[$name])) { if ($script:CAEsc6[$caN]) { $esc6cas += $caN } }
                if ($esc6cas.Count) {
                    $vulns += 'ESC6->ESC1'
                    Add-Finding 'Template' $name 'ESC6->ESC1' 'Critical' ("Client-auth template + low-priv enroll + issuing CA has EDITF SAN (ESC6): request a cert as ANY principal via SAN injection. Verify DC StrongCertificateBindingEnforcement. CA: " + ($esc6cas -join ',')) $lowEnrollNames
                }
            }
            if ($ess -and $clientAuth) { $vulns += 'ESC1'; Add-Finding 'Template' $name 'ESC1' 'Critical' 'Enrollee supplies subject + client auth, low-priv enroll' $lowEnrollNames }
            if ($anyPurpose)           { $vulns += 'ESC2'; Add-Finding 'Template' $name 'ESC2' 'Critical' 'Any-purpose EKU, low-priv enroll' $lowEnrollNames }
            if ($enrollAgent -and ($ekus -contains $EKU_CertReqAgent)) { $vulns += 'ESC3'; Add-Finding 'Template' $name 'ESC3' 'High' 'Certificate Request Agent EKU, low-priv enroll' $lowEnrollNames }
            if ($noSecExt -and $clientAuth) { $vulns += 'ESC9'; Add-Finding 'Template' $name 'ESC9' 'High' 'No security extension (szOID_NTDS_CA_SECURITY_EXT absent)' $lowEnrollNames }
            if ($ess -and $schema -eq 1) { $vulns += 'ESC15'; Add-Finding 'Template' $name 'ESC15' 'High' 'Schema v1 + enrollee supplies subject (CVE-2024-49019)' $lowEnrollNames }
            if ($clientAuth -and $policies.Count) {
                foreach ($pol in $policies) {
                    if ($OidGroupLinks.ContainsKey($pol)) {
                        $vulns += 'ESC13'; Add-Finding 'Template' $name 'ESC13' 'High' ("Issuance policy linked to group " + (Resolve-Sid $OidGroupLinks[$pol])) $lowEnrollNames
                    }
                }
            }
        }
        # ESC4 is independent of publication/approval - dangerous ACL or ownership
        if ($lowControl.Count) { $vulns += 'ESC4'; Add-Finding 'Template' $name 'ESC4' 'Critical' 'Low-priv principal has write/control over template' $lowCtrlNames }
        if ($ownerLow)         { $vulns += 'ESC4'; Add-Finding 'Template' $name 'ESC4' 'Critical' 'Template owned by low-priv principal' @((Resolve-Sid $rights.Owner)) }
        $vulns = $vulns | Select-Object -Unique

        $row = [pscustomobject]@{
            Name = $name; DisplayName = $display; Published = $published; Schema = $schema
            ClientAuth = $clientAuth; AnyPurpose = $anyPurpose; EnrollAgent = $enrollAgent
            EnrolleeSuppliesSubject = $ess; ManagerApproval = $mgrApproval; RASignatures = $raSig
            EKUs = ($ekus -join ','); Owner = (Resolve-Sid $rights.Owner)
            OwnerDefault = $ownerDefault
            EnrollmentRights = ($enrollNames -join '; ')
            LowPrivEnrollers = ($lowEnrollNames -join '; ')
            LowPrivControllers = ($lowCtrlNames -join '; ')
            Vulnerabilities = ($vulns -join ',')
        }
        $report.Add($row)

        if ($VulnerableOnly -and -not $vulns.Count) { continue }
        $color = if ($vulns.Count) { 'White' } else { 'DarkGray' }
        Write-Host ""
        Write-Host ("  {0}  ({1})" -f $name,$display) -ForegroundColor $color
        Write-Host ("      Published={0}  SchemaV{1}  ClientAuth={2}  AnyPurpose={3}  ESS={4}  MgrApproval={5}  RASigs={6}" -f $published,$schema,$clientAuth,$anyPurpose,$ess,$mgrApproval,$raSig) -ForegroundColor DarkGray
        if (-not $ownerDefault) { Write-Host ("      Owner (non-default): {0}" -f (Resolve-Sid $rights.Owner)) -ForegroundColor Yellow }
        if ($lowEnrollNames.Count) { Write-Host ("      Low-priv enrollers: {0}" -f ($lowEnrollNames -join ', ')) -ForegroundColor Yellow }
        if ($vulns.Count) {
            foreach ($f in ($script:Findings | Where-Object { $_.Object -eq $name -and $_.ObjectType -eq 'Template' })) {
                Write-Vuln $f.ESC ("{0}  -> {1}" -f $f.Detail, $f.Principals)
            }
        }
    }
    $report | Export-Csv -Path (Join-Path $OutputDir 'templates.csv') -NoTypeInformation -Encoding UTF8
    return $report
}

# ---------------------------------------------------------------------------
# Issuance policy OID -> group links (ESC13 support)
# ---------------------------------------------------------------------------
function Get-OidGroupLinks($ConfigNC) {
    $map = @{}
    try {
        $base = "CN=OID,CN=Public Key Services,CN=Services,$ConfigNC"
        $ds = New-Searcher $base '(objectClass=msPKI-Enterprise-Oid)' @('msPKI-Cert-Template-OID','msDS-OIDToGroupLink')
        foreach ($o in $ds.FindAll()) {
            if ($o.Properties['msds-oidtogrouplink'].Count -and $o.Properties['mspki-cert-template-oid'].Count) {
                $map[[string]$o.Properties['mspki-cert-template-oid'][0]] = [string]$o.Properties['msds-oidtogrouplink'][0]
            }
        }
    } catch {}
    return $map
}

# ---------------------------------------------------------------------------
# CA enumeration + CA-side ESC checks
# ---------------------------------------------------------------------------
function Get-CertUtilReg($Config,$Key) {
    try {
        $out = & certutil -config $Config -getreg $Key 2>$null
        return ($out -join "`n")
    } catch { return $null }
}

function Invoke-CAAudit($ConfigNC) {
    Write-Head "CERTIFICATE AUTHORITIES"
    $base = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$ConfigNC"
    $ds = New-Searcher $base '(objectClass=pKIEnrollmentService)' @('name','dNSHostName','certificateTemplates')
    $cas = $ds.FindAll()
    $published = @{}
    $caReport = New-Object System.Collections.Generic.List[object]

    foreach ($ca in $cas) {
        $caName = [string]$ca.Properties['name'][0]
        $caHost = [string]$ca.Properties['dnshostname'][0]
        $config = "$caHost\$caName"
        foreach ($tn in $ca.Properties['certificatetemplates']) {
            $t = [string]$tn
            $published[$t] = $true
            if (-not $script:TemplateCAs.ContainsKey($t)) { $script:TemplateCAs[$t] = @() }
            $script:TemplateCAs[$t] += $caName
        }

        Write-Host ""
        Write-Host ("  CA: {0}  ({1})" -f $caName,$caHost) -ForegroundColor White

        $esc6 = 'Unknown'; $esc11 = 'Unknown'; $esc16 = 'Unknown'; $esc7principals = @()
        if (-not $SkipCAConfig) {
            $edit = Get-CertUtilReg $config 'policy\EditFlags'
            if ($edit) {
                $m = [regex]::Match($edit,'=\s*([0-9a-fA-F]+)\s*\(')
                if ($m.Success) {
                    $val = [Convert]::ToInt64($m.Groups[1].Value,16)
                    $esc6 = (($val -band $EDITF_ATTRIBUTESUBJECTALTNAME2) -ne 0)
                    if ($esc6) { Add-Finding 'CA' $caName 'ESC6' 'Critical' 'EDITF_ATTRIBUTESUBJECTALTNAME2 enabled (any enroller can specify SAN)' @() }
                }
            }
            $iface = Get-CertUtilReg $config 'CA\InterfaceFlags'
            if ($iface) {
                $m = [regex]::Match($iface,'=\s*([0-9a-fA-F]+)\s*\(')
                if ($m.Success) {
                    $val = [Convert]::ToInt64($m.Groups[1].Value,16)
                    $esc11 = (($val -band $IF_ENFORCEENCRYPTICERTREQUEST) -eq 0)
                    if ($esc11) { Add-Finding 'CA' $caName 'ESC11' 'Medium' 'ICPR request encryption NOT enforced (relay to RPC enrollment)' @() }
                }
            }
            $dis = Get-CertUtilReg $config 'CA\DisableExtensionList'
            if ($dis) {
                $esc16 = ($dis -match [regex]::Escape($OID_SECURITY_EXT))
                if ($esc16) { Add-Finding 'CA' $caName 'ESC16' 'High' 'Security extension globally disabled on CA' @() }
            }
            # ESC7 - CA security via ICertAdmin2::GetCASecurity (returns SDDL)
            $esc7principals = Get-CASecurityLowPriv $config
            if ($esc7principals.Count) { Add-Finding 'CA' $caName 'ESC7' 'Critical' 'Low-priv principal has ManageCA / ManageCertificates' $esc7principals }
        }
        $script:CAEsc6[$caName] = ($esc6 -eq $true)

        $esc8 = 'Skipped'
        if (-not $SkipWebEnrollment) {
            $esc8 = Test-WebEnrollment $caHost
            if ($esc8 -and $esc8 -ne 'None') { Add-Finding 'CA' $caName 'ESC8' 'High' "Web enrollment reachable: $esc8 (NTLM relay to HTTP enrollment)" @() }
        }

        Write-Host ("      ESC6 (EDITF SAN)        : {0}" -f $esc6) -ForegroundColor (Pick $esc6)
        Write-Host ("      ESC11 (no req. encrypt) : {0}" -f $esc11) -ForegroundColor (Pick $esc11)
        Write-Host ("      ESC16 (sec ext disabled): {0}" -f $esc16) -ForegroundColor (Pick $esc16)
        if ($esc7principals.Count) { Write-Host ("      ESC7 principals         : {0}" -f ($esc7principals -join ', ')) -ForegroundColor Red }
        Write-Host ("      ESC8 (web enrollment)   : {0}" -f $esc8) -ForegroundColor (Pick ($esc8 -and $esc8 -ne 'None' -and $esc8 -ne 'Skipped'))

        $caReport.Add([pscustomobject]@{
            CA=$caName; Host=$caHost; ESC6=$esc6; ESC7=($esc7principals -join '; '); ESC8=$esc8; ESC11=$esc11; ESC16=$esc16
        })
    }
    $caReport | Export-Csv -Path (Join-Path $OutputDir 'cas.csv') -NoTypeInformation -Encoding UTF8
    return $published
}

function Pick($flag) { if ($flag -is [bool] -and $flag) { 'Red' } elseif ($flag -eq 'Unknown' -or $flag -eq 'Skipped') { 'DarkGray' } else { 'Green' } }

# ESC7: read the CA security descriptor via certutil (CA\Security, REG_BINARY hex dump),
# parse it, and return low-priv names that hold ManageCA / ManageCertificates.
function Get-CASecurityLowPriv($Config) {
    try {
        $out = & certutil -config $Config -getreg CA\Security 2>$null
        if (-not $out) { return @() }
        $bytes = New-Object System.Collections.Generic.List[byte]
        foreach ($line in ($out -split "`r?`n")) {
            $toks = @(($line.Trim() -split '\s+') | Where-Object { $_ -ne '' })
            if ($toks.Count -lt 2) { continue }
            $start = 0
            if ($toks[0] -notmatch '^[0-9a-fA-F]{2}$') { $start = 1 }   # skip the offset column
            for ($i = $start; $i -lt $toks.Count; $i++) {
                if ($toks[$i] -match '^[0-9a-fA-F]{2}$') { $bytes.Add([Convert]::ToByte($toks[$i],16)) }
                else { break }                                          # ASCII column starts here
            }
        }
        if ($bytes.Count -lt 20) { return @() }
        $rsd = New-Object System.Security.AccessControl.RawSecurityDescriptor(([byte[]]$bytes.ToArray()), 0)
        $low = New-Object System.Collections.Generic.List[string]
        foreach ($ace in $rsd.DiscretionaryAcl) {
            if ($ace.AceType -ne [System.Security.AccessControl.AceType]::AccessAllowed) { continue }
            $mask = $ace.AccessMask
            if ((($mask -band $CA_MANAGE_CA) -ne 0) -or (($mask -band $CA_MANAGE_CERT) -ne 0)) {
                $sid = $ace.SecurityIdentifier.Value
                if (Test-LowPriv $sid) { $low.Add((Resolve-Sid $sid)) }
            }
        }
        return ($low | Select-Object -Unique)
    } catch {
        Write-Warn2 ("      ESC7: could not read/parse CA security ({0})" -f $_.Exception.Message)
        return @()
    }
}

function Test-WebEnrollment($caHost) {
    $found = @()
    try { [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 } catch {}
    foreach ($scheme in @('http','https')) {
        foreach ($path in @('/certsrv/','/certsrv/certfnsh.asp','/certsrv/mscep/')) {
            $url = "$scheme`://$caHost$path"
            try {
                $req = [System.Net.WebRequest]::Create($url)
                $req.Method = 'GET'; $req.Timeout = 4000
                if ($scheme -eq 'https') { [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true } }
                try { $resp = $req.GetResponse(); $found += "$scheme$path($([int]$resp.StatusCode))"; $resp.Close() }
                catch [System.Net.WebException] {
                    $r = $_.Exception.Response
                    if ($r -and ([int]$r.StatusCode -eq 401 -or [int]$r.StatusCode -eq 200)) { $found += "$scheme$path(401)" }
                }
            } catch {}
        }
    }
    if ($found.Count) { return ($found -join ', ') } else { return 'None' }
}

# ---------------------------------------------------------------------------
# ESC10 - weak certificate mapping on DCs (remote registry)
# ---------------------------------------------------------------------------
function Invoke-DCCheck($ConfigNC) {
    Write-Head "DOMAIN CONTROLLERS (ESC10 - weak certificate mapping)"
    try {
        $rootDSE = Get-RootDSE
        $domainNC = $rootDSE.defaultNamingContext[0]
        $ds = New-Searcher $domainNC '(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))' @('dNSHostName')
        foreach ($d in $ds.FindAll()) {
            $dc = [string]$d.Properties['dnshostname'][0]
            try {
                $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine',$dc)
                $schan = $reg.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL')
                $kdc = $reg.OpenSubKey('SYSTEM\CurrentControlSet\Services\Kdc')
                $cmm = if ($schan) { $schan.GetValue('CertificateMappingMethods') } else { $null }
                $sbe = if ($kdc) { $kdc.GetValue('StrongCertificateBindingEnforcement') } else { $null }
                $weakSchan = ($cmm -ne $null) -and (($cmm -band 0x4) -ne 0)   # UPN mapping enabled
                $weakKdc = ($sbe -ne $null) -and ($sbe -eq 0)                 # enforcement disabled
                $dcColor = 'Green'; if ($weakSchan -or $weakKdc) { $dcColor = 'Red' }
                Write-Host ("  {0}: CertificateMappingMethods={1} StrongCertificateBindingEnforcement={2}" -f $dc,$cmm,$sbe) -ForegroundColor $dcColor
                if ($weakSchan) { Add-Finding 'DC' $dc 'ESC10' 'High' 'SCHANNEL CertificateMappingMethods allows weak UPN mapping (bit 0x4)' @() }
                if ($weakKdc)   { Add-Finding 'DC' $dc 'ESC10' 'High' 'Kdc StrongCertificateBindingEnforcement=0 (disabled)' @() }
            } catch { Write-Warn2 "  $dc : remote registry unavailable ($($_.Exception.Message))" }
        }
    } catch { Write-Warn2 "DC check failed: $($_.Exception.Message)" }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
Write-Head "AD CS ESC AUDIT  -  $(Get-Date)"
$rootDSE = Get-RootDSE
$ConfigNC = $rootDSE.configurationNamingContext[0]
Write-Info "Configuration NC: $ConfigNC"
Write-Info "Output folder   : $OutputDir"

Initialize-ThreatModel $ConfigNC
$oidLinks = Get-OidGroupLinks $ConfigNC
$published = Invoke-CAAudit $ConfigNC
$null = Invoke-TemplateAudit $ConfigNC $published $oidLinks
if (-not $SkipDCChecks) { Invoke-DCCheck $ConfigNC }

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
Write-Head "FINDINGS SUMMARY"
if ($script:Findings.Count -eq 0) {
    Write-Ok "No ESC findings under the low-privileged threat model."
} else {
    $script:Findings | Sort-Object Severity,ESC | Format-Table ESC,Severity,ObjectType,Object,Detail -AutoSize | Out-String -Width 4096 | Write-Host
}
$script:Findings | Export-Csv -Path (Join-Path $OutputDir 'findings.csv') -NoTypeInformation -Encoding UTF8
$script:Findings | ConvertTo-Json -Depth 5 | Out-File (Join-Path $OutputDir 'findings.json') -Encoding UTF8
Write-Info ("Findings: {0}  ->  {1}" -f $script:Findings.Count, $OutputDir)
Write-Info "Files: findings.csv, findings.json, templates.csv, cas.csv"
