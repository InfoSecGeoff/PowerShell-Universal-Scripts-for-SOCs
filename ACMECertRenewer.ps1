#Requires -Modules Posh-ACME
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Automated SSL Certificate Management for PowerShell Universal using ACME HTTP-01 validation

.DESCRIPTION
    This script provides complete SSL certificate lifecycle management without requiring IIS or any web server.
    It performs daily certificate expiration checks and automatically renews certificates using Let's Encrypt
    via the Posh-ACME module with HTTP-01 validation. The script temporarily opens port 80 only during 
    certificate validation, then immediately closes it for security. This is preferable to constant TXT record updates and storing records on firewalls.

    Key Features:
    - Daily automated certificate expiration monitoring
    - Secure port 80 management (opens only during validation)
    - No web server dependencies (uses WebSelfHost plugin)
    - Automatic certificate store installation
    - Comprehensive logging for SOC monitoring
    - PowerShell Universal integration ready

.PARAMETER Domain
    [REQUIRED] The domain name for which to request/renew the SSL certificate.
    Example: "psu.yourdomain.com"

.PARAMETER ContactEmail
    Email address for ACME account registration and renewal notifications.
    Default: "admin@yourdomain.com"

.PARAMETER ACMEServer
    ACME server to use for certificate requests.
    Valid values: "LetsEncrypt" (production), "LetsEncrypt-Staging" (testing)
    Default: "LetsEncrypt"

.PARAMETER CertificateStore
    Windows certificate store location for installing certificates.
    Default: "Cert:\LocalMachine\My"

.PARAMETER RenewalThresholdDays
    Number of days before expiration to trigger automatic renewal.
    Default: 7 days

.PARAMETER LogPath
    Full path for the log file.
    Default: "%ProgramData%\SSLManagement\ACMECertRenewer.log"

.PARAMETER CreateScheduledTask
    Creates a Windows scheduled task for daily certificate monitoring.
    Task runs at 3:00 AM daily as SYSTEM with highest privileges.

.PARAMETER ForceRenewal
    Forces certificate renewal regardless of expiration date.
    Useful for testing or immediate renewal needs.

.PARAMETER UseWebSelfHost
    Uses Posh-ACME's WebSelfHost plugin (no web server required).
    Default: $true (recommended for PowerShell Universal servers)

.EXAMPLE
    .\ACMECertRenewer.ps1 -Domain "psu.contoso.com" -ContactEmail "admin@contoso.com" -CreateScheduledTask
    
    Creates a scheduled task for daily monitoring and renewal of SSL certificate for psu.contoso.com

.EXAMPLE
    .\ACMECertRenewer.ps1 -Domain "test.contoso.com" -ACMEServer "LetsEncrypt-Staging" -ForceRenewal
    
    Forces immediate renewal of certificate using Let's Encrypt staging environment

.EXAMPLE
    .\ACMECertRenewer.ps1 -Domain "psu.contoso.com" -RenewalThresholdDays 14
    
    Checks certificate and renews if expiring within 14 days instead of default 7 days

.OUTPUTS
    String - Returns the certificate thumbprint upon successful renewal for use in PowerShell Universal configuration

.NOTES
    Author: Geoff Tankersley
    Version: 1.0
    Created: 2025
    
    Prerequisites:
    - Windows PowerShell 5.1+ or PowerShell Core 6+
    - Administrator privileges (for firewall and certificate store operations)
    - Posh-ACME module v4+ (auto-installed if missing)
    - Port 80 accessible from internet for HTTP-01 validation
    - Domain DNS pointing to the server's public IP
    
    Security Features:
    - Port 80 opened only during ACME validation (seconds/minutes)
    - Automatic firewall rule cleanup on success or failure
    - Secure certificate storage in LocalMachine store
    - Comprehensive audit logging
    
    Integration:
    - Designed for PowerShell Universal SSL certificate automation
    - Returns thumbprint for easy PSU configuration updates
    - Daily monitoring via Windows Task Scheduler
    - SOC-friendly logging and error handling
    
    Troubleshooting:
    - Check logs at %ProgramData%\SSLManagement\ACMECertRenewer.log
    - Ensure domain DNS points to server
    - Verify port 80 internet accessibility
    - Use -ForceRenewal for immediate testing
    - Use "LetsEncrypt-Staging" for testing without rate limits

.LINK
    https://poshac.me/docs/v4/
    
.LINK
    https://letsencrypt.org/docs/
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Domain,
    
    [Parameter()]
    [string]$ContactEmail = "admin@yourdomain.com",
    
    [Parameter()]
    [ValidateSet("LetsEncrypt", "LetsEncrypt-Staging")]
    [string]$ACMEServer = "LetsEncrypt",
    
    [Parameter()]
    [string]$CertificateStore = "Cert:\LocalMachine\My",
    
    [Parameter()]
    [int]$RenewalThresholdDays = 7,
    
    [Parameter()]
    [string]$LogPath = "$env:ProgramData\SSLManagement\ACMECertRenewer.log",
    
    [Parameter()]
    [string]$WebRootPath = "$env:SystemDrive\inetpub\wwwroot",
    
    [Parameter()]
    [switch]$CreateScheduledTask = $false,
    
    [Parameter()]
    [switch]$ForceRenewal = $false,
    
    [Parameter()]
    [switch]$UseWebSelfHost = $true
)

# Global variables
$Script:LogPath = $LogPath
$Script:Domain = $Domain
$Script:WebRootPath = $WebRootPath

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "DEBUG")]
        [string]$Level = "INFO"
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Level] $Message"
    
    # Ensure log directory exists
    $LogDir = Split-Path $Script:LogPath -Parent
    if (-not (Test-Path $LogDir)) {
        New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
    }
    
    Write-Host $LogMessage -ForegroundColor $(
        switch($Level) {
            "ERROR" { "Red" }
            "WARN" { "Yellow" }
            "DEBUG" { "Cyan" }
            default { "Green" }
        }
    )
    Add-Content -Path $Script:LogPath -Value $LogMessage
}

function Test-Port80Available {
    Write-Log "Testing if port 80 is available" -Level "DEBUG"
    try {
        $TcpListener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Any, 80)
        $TcpListener.Start()
        $TcpListener.Stop()
        Write-Log "Port 80 is available for use" -Level "DEBUG"
        return $true
    }
    catch {
        Write-Log "Port 80 is not available: $($_.Exception.Message)" -Level "WARN"
        return $false
    }
}

function Open-Port80 {
    Write-Log "Opening port 80 for ACME HTTP-01 challenge"
    try {
        # Remove any existing rule first
        $ExistingRule = Get-NetFirewallRule -DisplayName "ACME HTTP-01 Challenge" -ErrorAction SilentlyContinue
        if ($ExistingRule) {
            Write-Log "Removing existing firewall rule" -Level "DEBUG"
            Remove-NetFirewallRule -DisplayName "ACME HTTP-01 Challenge" -Confirm:$false
        }
        
        # Add new firewall rule
        New-NetFirewallRule -DisplayName "ACME HTTP-01 Challenge" -Direction Inbound -Protocol TCP -LocalPort 80 -Action Allow -Profile Any -Description "Temporary rule for ACME HTTP-01 certificate validation" | Out-Null
        Write-Log "Firewall rule created - port 80 opened"
        
        # Verify rule exists
        $Rule = Get-NetFirewallRule -DisplayName "ACME HTTP-01 Challenge" -ErrorAction SilentlyContinue
        if ($Rule) {
            Write-Log "Port 80 firewall rule verified" -Level "DEBUG"
            return $true
        } else {
            throw "Failed to verify firewall rule creation"
        }
    }
    catch {
        Write-Log "Failed to open port 80: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function Close-Port80 {
    Write-Log "Closing port 80 after ACME challenge"
    try {
        $ExistingRule = Get-NetFirewallRule -DisplayName "ACME HTTP-01 Challenge" -ErrorAction SilentlyContinue
        if ($ExistingRule) {
            Remove-NetFirewallRule -DisplayName "ACME HTTP-01 Challenge" -Confirm:$false
            Write-Log "Port 80 firewall rule removed - port closed"
        } else {
            Write-Log "No ACME firewall rule found to remove" -Level "DEBUG"
        }
        return $true
    }
    catch {
        Write-Log "Failed to close port 80: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function Initialize-WebRoot {
    Write-Log "Initializing web root directory structure" -Level "DEBUG"
    try {
        # Ensure web root exists
        if (-not (Test-Path $Script:WebRootPath)) {
            Write-Log "Creating web root directory: $Script:WebRootPath"
            New-Item -ItemType Directory -Path $Script:WebRootPath -Force | Out-Null
        }
        
        # Ensure .well-known/acme-challenge directory exists
        $ChallengeDir = Join-Path $Script:WebRootPath ".well-known\acme-challenge"
        if (-not (Test-Path $ChallengeDir)) {
            Write-Log "Creating ACME challenge directory: $ChallengeDir"
            New-Item -ItemType Directory -Path $ChallengeDir -Force | Out-Null
        }
        
        Write-Log "Web root initialized successfully" -Level "DEBUG"
        return $true
    }
    catch {
        Write-Log "Failed to initialize web root: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function Get-ExistingPAOrder {
    param([string]$Domain)
    
    Write-Log "Checking for existing Posh-ACME order for domain: $Domain" -Level "DEBUG"
    try {
        # Get all orders and find one matching our domain
        $Orders = Get-PAOrder -List
        $MatchingOrder = $Orders | Where-Object { 
            $_.MainDomain -eq $Domain -or $_.SANs -contains $Domain 
        } | Sort-Object expires -Descending | Select-Object -First 1
        
        if ($MatchingOrder) {
            Write-Log "Found existing order for $Domain - Status: $($MatchingOrder.status)" -Level "DEBUG"
            return $MatchingOrder
        } else {
            Write-Log "No existing order found for $Domain" -Level "DEBUG"
            return $null
        }
    }
    catch {
        Write-Log "Error checking for existing orders: $($_.Exception.Message)" -Level "ERROR"
        return $null
    }
}

function Test-CertificateRenewalNeeded {
    Write-Log "=== Starting SSL Certificate Expiration Check ===" -Level "INFO"
    
    # Check for existing Posh-ACME order first
    $ExistingOrder = Get-ExistingPAOrder -Domain $Script:Domain
    
    if ($ExistingOrder) {
        # Use Posh-ACME's built-in expiration logic
        $ExpirationDate = [datetime]$ExistingOrder.expires
        $DaysUntilExpiry = ($ExpirationDate - (Get-Date)).Days
        
        Write-Log "Posh-ACME order found - expires in $DaysUntilExpiry days on $ExpirationDate"
        
        if ($ForceRenewal) {
            Write-Log "Force renewal requested - proceeding with renewal" -Level "WARN"
            return $true
        }
        
        if ($DaysUntilExpiry -le $RenewalThresholdDays) {
            Write-Log "Certificate expires within $RenewalThresholdDays days - renewal needed" -Level "WARN"
            return $true
        } else {
            Write-Log "Certificate is still valid for $DaysUntilExpiry days - no renewal needed"
            return $false
        }
    } else {
        # Check certificate store as fallback
        $Certificate = Get-ChildItem -Path $CertificateStore | Where-Object { 
            $_.Subject -like "*CN=$Script:Domain*" -or $_.DnsNameList.Unicode -contains $Script:Domain 
        } | Sort-Object NotAfter -Descending | Select-Object -First 1
        
        if ($Certificate) {
            $DaysUntilExpiry = ($Certificate.NotAfter - (Get-Date)).Days
            Write-Log "Certificate found in store - expires in $DaysUntilExpiry days on $($Certificate.NotAfter)"
            
            if ($ForceRenewal -or $DaysUntilExpiry -le $RenewalThresholdDays) {
                Write-Log "Certificate needs renewal" -Level "WARN"
                return $true
            } else {
                Write-Log "Certificate is still valid - no renewal needed"
                return $false
            }
        } else {
            Write-Log "No certificate found for $Script:Domain - initial certificate needed" -Level "WARN"
            return $true
        }
    }
}

function Request-NewCertificate {
    Write-Log "Starting certificate request/renewal process for $Script:Domain"
    
    try {
        # Ensure Posh-ACME is available and up to date
        if (-not (Get-Module -ListAvailable -Name Posh-ACME)) {
            Write-Log "Installing Posh-ACME module" -Level "WARN"
            Install-Module -Name Posh-ACME -Force -Scope AllUsers
        }
        
        Import-Module Posh-ACME -Force
        
        # Set ACME server
        Set-PAServer -DirectoryUrl $ACMEServer
        Write-Log "Using ACME server: $ACMEServer"
        
        # Get or create ACME account
        $Account = Get-PAAccount
        if (-not $Account) {
            Write-Log "Creating new ACME account for: $ContactEmail"
            $Account = New-PAAccount -Contact $ContactEmail -AcceptTOS
        }
        Write-Log "Using ACME account ID: $($Account.Id)" -Level "DEBUG"
        
        # Check for existing order
        $ExistingOrder = Get-ExistingPAOrder -Domain $Script:Domain
        
        if ($ExistingOrder) {
            Write-Log "Using existing order for renewal"
            # Set the current order context
            Set-PAOrder -MainDomain $Script:Domain
        }
        
        # Configure plugin arguments for WebSelfHost (no web server needed)
        Write-Log "Using WebSelfHost plugin for HTTP-01 challenge (no web server required)"
        $PluginArgs = @{}
        $Plugin = 'WebSelfHost'
        
        # Open port 80 for challenge
        if (-not (Open-Port80)) {
            throw "Unable to open port 80 for HTTP-01 challenge"
        }
        
        try {
            if ($ExistingOrder) {
                # Use Submit-Renewal for existing orders (recommended approach)
                Write-Log "Attempting certificate renewal using Submit-Renewal"
                
                if ($ForceRenewal) {
                    $Certificate = Submit-Renewal -Force -PluginArgs $PluginArgs
                } else {
                    $Certificate = Submit-Renewal -PluginArgs $PluginArgs
                }
            } else {
                # Create new certificate for first-time requests
                Write-Log "Creating new certificate order using New-PACertificate"
                $Certificate = New-PACertificate -Domain $Script:Domain -Plugin $Plugin -PluginArgs $PluginArgs -AcceptTOS -Contact $ContactEmail
            }
            
            if (-not $Certificate) {
                throw "Certificate request/renewal failed - no certificate returned"
            }
            
            Write-Log "Certificate generated/renewed successfully"
            Write-Log "Certificate details: Subject=$($Certificate.Subject), NotAfter=$($Certificate.NotAfter)"
            
            # Install certificate to Windows certificate store if requested
            if ($Certificate.PfxFile -and (Test-Path $Certificate.PfxFile)) {
                $ImportedCert = Import-PfxCertificate -FilePath $Certificate.PfxFile -CertStoreLocation $CertificateStore -Exportable
                
                if ($ImportedCert) {
                    Write-Log "Certificate installed to store - Thumbprint: $($ImportedCert.Thumbprint)"
                    
                    # Clean up old certificates for the same domain
                    $OldCertificates = Get-ChildItem -Path $CertificateStore | Where-Object { 
                        ($_.Subject -like "*CN=$Script:Domain*" -or $_.DnsNameList.Unicode -contains $Script:Domain) -and 
                        $_.Thumbprint -ne $ImportedCert.Thumbprint 
                    }
                    
                    foreach ($OldCert in $OldCertificates) {
                        Write-Log "Removing old certificate with thumbprint: $($OldCert.Thumbprint)" -Level "DEBUG"
                        Remove-Item -Path "$CertificateStore\$($OldCert.Thumbprint)" -Force -ErrorAction SilentlyContinue
                    }
                    
                    return $ImportedCert.Thumbprint
                } else {
                    Write-Log "Certificate generated but failed to install to certificate store" -Level "WARN"
                    return $Certificate.Thumbprint
                }
            } else {
                Write-Log "Certificate generated - PFX file: $($Certificate.PfxFile)"
                return $Certificate.Thumbprint
            }
        }
        finally {
            # Always close port 80
            Close-Port80
        }
    }
    catch {
        Write-Log "Certificate request/renewal failed: $($_.Exception.Message)" -Level "ERROR"
        Close-Port80  # Ensure port is closed on error
        throw
    }
}

function New-AutoRenewalTask {
    Write-Log "Creating scheduled task for daily SSL certificate check"
    
    try {
        $ScriptPath = $MyInvocation.ScriptName
        if (-not $ScriptPath) {
            $ScriptPath = "$env:ProgramData\SSLManagement\ACMECertRenewer.ps1"
            Write-Log "Saving script to: $ScriptPath"
            
            # Ensure directory exists
            $ScriptDir = Split-Path $ScriptPath -Parent
            if (-not (Test-Path $ScriptDir)) {
                New-Item -ItemType Directory -Path $ScriptDir -Force | Out-Null
            }
            
            # Copy current script content to the target location
            if ($PSCommandPath) {
                Copy-Item -Path $PSCommandPath -Destination $ScriptPath -Force
            }
        }
        
        $TaskName = "SSL Certificate Auto-Renewal - $Script:Domain"
        $Arguments = "-ExecutionPolicy Bypass -File `"$ScriptPath`" -Domain `"$Script:Domain`" -ContactEmail `"$ContactEmail`" -ACMEServer `"$ACMEServer`" -WebRootPath `"$Script:WebRootPath`""
        
        if ($UseWebSelfHost) {
            $Arguments += " -UseWebSelfHost"
        }
        
        # Create the scheduled task
        $Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument $Arguments
        $Trigger = New-ScheduledTaskTrigger -Daily -At "03:00AM"
        $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable
        $Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        
        Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -Principal $Principal -Description "Daily SSL certificate expiration check and auto-renewal for $Script:Domain using Posh-ACME" -Force | Out-Null
        
        Write-Log "Scheduled task created successfully: $TaskName"
        Write-Log "Task will run daily at 3:00 AM to check certificate expiration"
    }
    catch {
        Write-Log "Failed to create scheduled task: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

# Main execution
try {
    Write-Log "=== SSL Certificate Auto-Renewal Started (Posh-ACME v4 Compatible) ==="
    Write-Log "Domain: $Script:Domain"
    Write-Log "Contact Email: $ContactEmail"
    Write-Log "ACME Server: $ACMEServer"
    Write-Log "Renewal Threshold: $RenewalThresholdDays days"
    Write-Log "Certificate Store: $CertificateStore"
    Write-Log "Plugin: $(if ($UseWebSelfHost) { 'WebSelfHost' } else { "WebRoot (Path: $Script:WebRootPath)" })"
    
    # Create scheduled task if requested
    if ($CreateScheduledTask) {
        New-AutoRenewalTask
        Write-Log "Scheduled task created - script will run daily automatically"
    }
    
    # Check if renewal is needed
    $RenewalNeeded = Test-CertificateRenewalNeeded
    
    if ($RenewalNeeded) {
        Write-Log "=== Certificate Renewal Required - Starting Process ===" -Level "WARN"
        
        # Verify port 80 availability (warning only)
        if (-not (Test-Port80Available)) {
            Write-Log "Port 80 appears to be in use - will attempt to use firewall rule anyway" -Level "WARN"
        }
        
        # Request new certificate
        $NewThumbprint = Request-NewCertificate
        
        Write-Log "=== Certificate Renewal Completed Successfully ===" -Level "INFO"
        Write-Log "Certificate Thumbprint: $NewThumbprint" -Level "INFO"
        Write-Log "Update your PowerShell Universal configuration with this thumbprint"
        
        # Output thumbprint for scripts/automation
        Write-Output $NewThumbprint
    } else {
        Write-Log "=== Certificate Check Completed - No Renewal Needed ==="
    }
}
catch {
    Write-Log "=== SSL Certificate Auto-Renewal Failed ===" -Level "ERROR"
    Write-Log "Error: $($_.Exception.Message)" -Level "ERROR"
    
    # Ensure port 80 is closed even on error
    Close-Port80
    
    exit 1
}

Write-Log "=== SSL Certificate Auto-Renewal Process Finished ==="
