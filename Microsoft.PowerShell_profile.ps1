### PowerShell Profile Refactor
### Version 1.05 - Refactored

# Initial GitHub.com connectivity check with 1 second timeout
$canConnectToGitHub = Test-Connection github.com -Count 1 -Quiet -TimeoutSeconds 1

# Import Modules and External Profiles
# Ensure Terminal-Icons module is installed before importing
if (-not (Get-Module -ListAvailable -Name Terminal-Icons)) {
    Install-Module -Name Terminal-Icons -Scope CurrentUser -Force -SkipPublisherCheck
}
Import-Module -Name Terminal-Icons
$ChocolateyProfile = "$env:ChocolateyInstall\helpers\chocolateyProfile.psm1"
if (Test-Path($ChocolateyProfile)) {
    Import-Module "$ChocolateyProfile"
}

# Check for Profile Updates
function UpdateProfile {
    param (
        [switch]$ForceUpdate = $false
    )

    $lastUpdated = (Get-Item $PROFILE).LastWriteTime
    $timeSinceUpdate = (Get-Date) - $lastUpdated
    $nextUpdateDue = $lastUpdated.AddDays(1)

    if ($timeSinceUpdate.TotalDays -lt 1 -and -not $ForceUpdate) {
        $nextUpdateInHours = [Math]::Floor((24 - $timeSinceUpdate.TotalHours))
        $nextUpdateInMinutes = [Math]::Floor((60 - $timeSinceUpdate.TotalMinutes) % 60)
        Write-Host "Next profile update: $nextUpdateInHours hour(s) and $nextUpdateInMinutes minute(s). Use 'ReloadProfile' to update now." -ForegroundColor Magenta
        return
    }

    Write-Host "Initiating profile update check from GitHub......" -ForegroundColor Cyan
    $tempFile = "$env:temp/Microsoft.PowerShell_profile.ps1"

    try {
        $url = "https://raw.githubusercontent.com/BetaBrainz/powershell-profile/main/Microsoft.PowerShell_profile.ps1"
        Invoke-RestMethod $url -OutFile $tempFile

        $oldhash = Get-FileHash $PROFILE -ErrorAction SilentlyContinue
        $newhash = Get-FileHash $tempFile

        if ($oldhash.Hash -ne $newhash.Hash) {
            Write-Host "A new version of the profile has been detected. Updating profile..." -ForegroundColor Yellow
            Copy-Item -Path $tempFile -Destination $PROFILE -Force
            Write-Host "Profile has been updated successfully. Please restart your shell to reflect changes." -ForegroundColor Magenta
        } else {
            Write-Host "Your PowerShell profile is already up to date." -ForegroundColor Green
        }
    } catch {
        Write-Error "Failed to check or update profile. Error: $_"
    } finally {
        Remove-Item $tempFile -ErrorAction SilentlyContinue
    }
}
UpdateProfile

function Update-PowerShell {
    if (-not $global:canConnectToGitHub) {
        Write-Host "Skipping PowerShell update check due to GitHub.com not responding within 1 second." -ForegroundColor Yellow
        return
    }

    try {
        Write-Host "Checking for PowerShell updates..." -ForegroundColor Cyan
        $updateNeeded = $false
        $currentVersion = $PSVersionTable.PSVersion.ToString()
        $gitHubApiUrl = "https://api.github.com/repos/PowerShell/PowerShell/releases/latest"
        $latestReleaseInfo = Invoke-RestMethod -Uri $gitHubApiUrl
        $latestVersion = $latestReleaseInfo.tag_name.Trim('v')
        if ($currentVersion -lt $latestVersion) {
            $updateNeeded = $true
        }

        if ($updateNeeded) {
            Write-Host "Updating PowerShell..." -ForegroundColor Yellow
            winget upgrade "Microsoft.PowerShell" --accept-source-agreements --accept-package-agreements
            Write-Host "PowerShell has been updated. Please restart your shell to reflect changes" -ForegroundColor Magenta
        } else {
            Write-Host "Your PowerShell is up to date." -ForegroundColor Green
        }
    } catch {
        Write-Error "Failed to update PowerShell. Error: $_"
    }
}
Update-PowerShell


# Admin Check and Prompt Customization
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
function prompt {
    if ($isAdmin) { "[" + (Get-Location) + "] # " } else { "[" + (Get-Location) + "] $ " }
}
$adminSuffix = if ($isAdmin) { " [ADMIN]" } else { "" }
$Host.UI.RawUI.WindowTitle = "PowerShell {0}$adminSuffix" -f $PSVersionTable.PSVersion.ToString()

# Utility Functions
function Test-CommandExists {
    param($command)
    $exists = $null -ne (Get-Command $command -ErrorAction SilentlyContinue)
    return $exists
}

# Editor Configuration
$EDITOR = if (Test-CommandExists nvim) { 'nvim' }
          elseif (Test-CommandExists pvim) { 'pvim' }
          elseif (Test-CommandExists vim) { 'vim' }
          elseif (Test-CommandExists vi) { 'vi' }
          elseif (Test-CommandExists code) { 'code' }
          elseif (Test-CommandExists notepad++) { 'notepad++' }
          elseif (Test-CommandExists sublime_text) { 'sublime_text' }
          else { 'notepad' }
Set-Alias -Name vim -Value $EDITOR

function Edit-Profile {
    vim $PROFILE.CurrentUserAllHosts
}
function touch($file) { "" | Out-File $file -Encoding ASCII }
function ff($name) {
    Get-ChildItem -recurse -filter "*${name}*" -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Output "$($_.directory)\$($_)"
    }
}

# Network Utilities
function GetPublicIP { (Invoke-WebRequest http://ifconfig.me/ip).Content }

# System Utilities
function uptime {
    if ($PSVersionTable.PSVersion.Major -eq 5) {
        Get-WmiObject win32_operatingsystem | Select-Object @{Name='LastBootUpTime'; Expression={$_.ConverttoDateTime($_.lastbootuptime)}} | Format-Table -HideTableHeaders
    } else {
        net statistics workstation | Select-String "since" | ForEach-Object { $_.ToString().Replace('Statistics since ', '') }
    }
}

function ReloadProfile {
    & $profile
}

function unzip ($file) {
    Write-Output("Extracting", $file, "to", $pwd)
    $fullFile = Get-ChildItem -Path $pwd -Filter $file | ForEach-Object { $_.FullName }
    Expand-Archive -Path $fullFile -DestinationPath $pwd
}
function hb {
    if ($args.Length -eq 0) {
        Write-Error "No file path specified."
        return
    }
    
    $FilePath = $args[0]
    
    if (Test-Path $FilePath) {
        $Content = Get-Content $FilePath -Raw
    } else {
        Write-Error "File path does not exist."
        return
    }
    
    $uri = "http://bin.christitus.com/documents"
    try {
        $response = Invoke-RestMethod -Uri $uri -Method Post -Body $Content -ErrorAction Stop
        $hasteKey = $response.key
        $url = "http://bin.christitus.com/$hasteKey"
        Write-Output $url
    } catch {
        Write-Error "Failed to upload the document. Error: $_"
    }
}
function grep($regex, $dir) {
    if ( $dir ) {
        Get-ChildItem $dir | select-string $regex
        return
    }
    $input | select-string $regex
}

function df {
    get-volume
}

function sed($file, $find, $replace) {
    (Get-Content $file).replace("$find", $replace) | Set-Content $file
}

function which($name) {
    Get-Command $name | Select-Object -ExpandProperty Definition
}

function export($name, $value) {
    set-item -force -path "env:$name" -value $value;
}

function pkill($name) {
    Get-Process $name -ErrorAction SilentlyContinue | Stop-Process
}

function fkill { Stop-Process -Name $args[0] }

function pipupdate($name) {
    pip install --upgrade ((pip freeze) -replace '==.+','')
}

function spotx($name) {
    iex "& { $(iwr -useb 'https://spotx-official.github.io/run.ps1') } -m -new_theme"
}

function pgrep($name) {
    Get-Process $name
}

function head {
  param($Path, $n = 10)
  Get-Content $Path -Head $n
}

function tail {
  param($Path, $n = 10)
  Get-Content $Path -Tail $n
}

# Quick File Creation
function nf { param($name) New-Item -ItemType "file" -Path . -Name $name }

# Directory Management
function mkcd { param($dir) mkdir $dir -Force; Set-Location $dir }

### Quality of Life Aliases

# Navigation Shortcuts
function docs { Set-Location -Path $HOME\Documents }

function dtop { Set-Location -Path $HOME\Desktop }

# Quick Access to Editing the Profile
function ep { vim $PROFILE }

# Enhanced Listing
function la { Get-ChildItem -Path . -Force | Format-Table -AutoSize }
function ll { Get-ChildItem -Path . -Force -Hidden | Format-Table -AutoSize }

# Git Shortcuts
function gs { git status }

function ga { git add . }

function gc { param($m) git commit -m "$m" }

function gp { git push }

function g { z Github }

function gcom {
    git add .
    git commit -m "$args"
}
function lazyg {
    git add .
    git commit -m "$args"
    git push
}

function ss {git status --short}

# Quick Access to System Information
function sysinfo { Get-ComputerInfo }

# Networking Utilities
function flushdns { Clear-DnsClientCache }

# Clipboard Utilities
function cpy { Set-Clipboard $args[0] }

function pst { Get-Clipboard }

function SystemResourceUsage {
    $cpuLoad = Get-Counter '\Processor(_Total)\% Processor Time' | Select-Object -ExpandProperty countersamples | Select-Object -ExpandProperty cookedvalue
    $memUsage = Get-WmiObject Win32_OperatingSystem | Select-Object @{Name="MemoryUsage";Expression={"{0:N2}" -f ((($_.TotalVisibleMemorySize - $_.FreePhysicalMemory)*100)/ $_.TotalVisibleMemorySize)}}
    Write-Output "CPU Load: $cpuLoad%"
    Write-Output "Memory Usage: $($memUsage.MemoryUsage)%"
}

function NetworkSpeed {
    try {
        $output = speedtest-cli --simple
        $lines = $output -split "\n"

        foreach ($line in $lines) {
            if ($line -like "*Ping*") {
                Write-Host $line -ForegroundColor Cyan
            }
            elseif ($line -like "*Download*") {
                Write-Host $line -ForegroundColor Green
            }
            elseif ($line -like "*Upload*") {
                Write-Host $line -ForegroundColor Magenta
            }
            else {
                Write-Host $line
            }
        }
    } catch {
        Write-Host "Failed to perform speed test. Error: $_" -ForegroundColor Red
    }
}

function wifinetwork{netsh wlan show profile}

function thiswifi{netsh wlan show profile $args key=clear | findstr “Key Content”}

function weather{curl wttr.in/$args}

function qr{curl qrenco.de/$args}

function googleSearch{start www.google.com/search?q=$args}
set-alias gs googleSearch

function youtubeSearch{start www.youtube.com/search?q=$args}
set-alias ys youtubeSearch

function scanfile { sfc /scannow }

function checkhealth { DISM /Online /Cleanup-Image /CheckHealth }

function scanhealth { DISM /Online /Cleanup-Image /ScanHealth }

function restorehealth { DISM /Online /Cleanup-Image /RestoreHealth }

function ipflush { ipconfig /flushdns }

function shutdown { shutdown /s }

function restart { shutdown /r }

function Edit-Profile { notepad++ "$Env:USERPROFILE\Documents\PowerShell\Microsoft.PowerShell_profile.ps1" }


function cleaner{	
	# Function to clean temporary files
	function Clean-TempFiles {
		Write-Host "Cleaning temporary files..."
		Get-ChildItem -Path $env:TEMP -Recurse | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
	}

	# Function to clean the Recycle Bin
	function Clean-RecycleBin {
		Write-Host "Emptying the Recycle Bin..."
		(New-Object -ComObject Shell.Application).NameSpace(0xA).Items() | ForEach { Remove-Item $_.Path -Force -Recurse -ErrorAction SilentlyContinue }
	}

	# Function to perform disk cleanup
	function Perform-DiskCleanup {
		Write-Host "Performing disk cleanup..."
		$cleanmgr = Start-Process cleanmgr -ArgumentList "/sagerun:1" -PassThru
		$cleanmgr.WaitForExit()
	}	

	# Running all clean-up tasks
	Clean-TempFiles
	Clean-RecycleBin
	Perform-DiskCleanup

	Write-Host "System cleanup complete."
}

function ipchange{
# Display network adapters to the user
Write-Host "Available Network Adapters and their Interface Indexes:"
Get-NetAdapter | Format-Table Name, InterfaceIndex, Status

# Prompt for Interface Index and validate
$interfaceIndex = $null
do {
    $interfaceIndex = Read-Host "Enter the Interface Index from the list above"
    if (-not $interfaceIndex -or $interfaceIndex -eq '') {
        Write-Host "Interface Index cannot be empty, please enter a valid number."
    }
    if (-not (Get-NetAdapter | Where-Object InterfaceIndex -eq $interfaceIndex)) {
        Write-Host "Invalid Interface Index entered. Please enter a number from the list above."
        $interfaceIndex = $null
    }
} while (-not $interfaceIndex)

$ipAddress = Read-Host "Enter the new IP Address"
$subnetMask = Read-Host "Enter the Subnet Mask"

# Check if subnet mask is empty and set default value
if ([string]::IsNullOrWhiteSpace($subnetMask)) {
    $subnetMask = "255.255.255.0"
}

# Convert the subnet mask to prefix length
$prefixLength = ConvertTo-PrefixLength -SubnetMask $subnetMask

# Remove the existing IP address
try {
    Get-NetIPAddress -InterfaceIndex $interfaceIndex | Remove-NetIPAddress -Confirm:$false
    Write-Host "Existing IP Address(es) removed."
} catch {
    Write-Error "Failed to remove existing IP Address. Error: $_"
}

# Set the IP Address
try {
    New-NetIPAddress -InterfaceIndex $interfaceIndex -IPAddress $ipAddress -PrefixLength $prefixLength
    Write-Host "IP Address has been changed successfully."
} catch {
    Write-Error "Failed to change IP Address. Error: $_"
}
}

# Enhanced PowerShell Experience
Set-PSReadLineOption -Colors @{
    Command = 'Yellow'
    Parameter = 'Green'
    String = 'DarkCyan'
}

## Final Line to set prompt
oh-my-posh init pwsh --config https://raw.githubusercontent.com/JanDeDobbeleer/oh-my-posh/main/themes/di4am0nd.omp.json | Invoke-Expression
if (Get-Command zoxide -ErrorAction SilentlyContinue) {
    Invoke-Expression (& { (zoxide init powershell | Out-String) })
} else {
    Write-Host "zoxide command not found. Attempting to install via winget..."
    try {
        winget install -e --id ajeetdsouza.zoxide
        Write-Host "zoxide installed successfully. Initializing..."
        Invoke-Expression (& { (zoxide init powershell | Out-String) })
    } catch {
        Write-Error "Failed to install zoxide. Error: $_"
    }
}

function ShowFunctions {
    Write-Host "Available custom functions with descriptions:" -ForegroundColor Cyan

    # Profile Management
    Write-Host "`nProfile Management:" -ForegroundColor Green
    Write-Output "  - UpdateProfile: Checks and updates the PowerShell profile from GitHub. Usage: UpdateProfile -ForceUpdate"
    Write-Output "  - EditProfile: Opens the current user's all hosts profile in the default editor. Usage: EditProfile"
    Write-Output "  - ReloadProfile: Reloads the PowerShell profile. Usage: ReloadProfile"
    Write-Output "  - UpdatePowerShell: Checks and updates PowerShell if a newer version is available. Usage: UpdatePowerShell"

    # System Utilities
    Write-Host "`nSystem Utilities:" -ForegroundColor Green
    Write-Output "  - Uptime: Shows system uptime since the last boot. Usage: Uptime"
    Write-Output "  - Sysinfo: Retrieves detailed system information. Usage: Sysinfo"

    # Network Utilities
    Write-Host "`nNetwork Utilities:" -ForegroundColor Green
    Write-Output "  - GetPublicIP: Retrieves the public IP address. Usage: GetPublicIP"
    Write-Output "  - FlushDNS: Clears the DNS client cache. Usage: FlushDNS"
    Write-Output "  - IPchange: Tries to change IP allocated to system. Usage: ipchange"
	Write-Output "  - NetworkSpeed: Test Network Speed. Usage: NetworkSpeed"
	Write-Output "  - wifinetwork: Get Wifi profiles. Usage: wifinetwork"
	Write-Output "  - thiswifi: Get Wifi Content. Usage: thiswifi"

    # File Management
    Write-Host "`nFile Management:" -ForegroundColor Green
    Write-Output "  - OpenDir: Opens the current directory in Windows Explorer. Usage: OpenDir"
    Write-Output "  - unzip: Extracts a zip file to the specified directory. Usage: unzip 'file.zip'"
    Write-Output "  - grep: Searches for patterns in files. Usage: grep 'regex' 'path'"
    Write-Output "  - df: Displays disk space usage. Usage: df"
    Write-Output "  - sed: Replaces text in a file. Usage: sed 'file' 'find' 'replace'"
    Write-Output "  - which: Finds the location of a command. Usage: which 'cmd'"
    Write-Output "  - head: Displays the first 'n' lines of a file. Usage: head 'file' 10"
    Write-Output "  - tail: Displays the last 'n' lines of a file. Usage: tail 'file' 10"
    Write-Output "  - nf: Creates a new file. Usage: nf 'filename'"
    Write-Output "  - mkcd: Creates a new directory and changes to it. Usage: mkcd 'dirname'"
    Write-Output "  - touch: Creates or updates the timestamp of a file. Usage: touch 'file'"
    Write-Output "  - ff: Finds files containing a string in their names. Usage: ff 'pattern'"

    # Process Management
    Write-Host "`nProcess Management:" -ForegroundColor Green
    Write-Output "  - pkill: Terminates processes by name. Usage: pkill 'processName'"
    Write-Output "  - pgrep: Lists all processes by name. Usage: pgrep 'processName'"
    Write-Output "  - fkill: Force stops a process by name. Usage: fkill 'processName'"

    # Git Utilities
    Write-Host "`nGit Utilities:" -ForegroundColor Green
    Write-Output "  - gs: Runs the 'git status' command. Usage: gs"
    Write-Output "  - ga: Stages all changes in git. Usage: ga"
    Write-Output "  - gc: Commits staged changes in git with a provided message. Usage: gc 'message'"
    Write-Output "  - gp: Pushes committed changes to a remote git repository. Usage: gp"
    Write-Output "  - g: Navigates to the GitHub directory. Usage: g"
    Write-Output "  - gcom: Stages and commits all changes in git with a specified message. Usage: gcom 'message'"
    Write-Output "  - lazyg: Stages, commits, and pushes all changes in git. Usage: lazyg 'message'"

    # Clipboard Utilities
    Write-Host "`nClipboard Utilities:" -ForegroundColor Green
    Write-Output "  - cpy: Copies text to the clipboard. Usage: cpy 'text'"
    Write-Output "  - pst: Retrieves the current content of the clipboard. Usage: pst"
    Write-Output "  - CopyCsvToClipboard: Copies contents of a CSV file to the clipboard. Usage: CopyCsvToClipboard 'file.csv'"

    # Navigation Shortcuts
    Write-Host "`nNavigation Shortcuts:" -ForegroundColor Green
    Write-Output "  - docs: Navigates to the Documents folder. Usage: docs"
    Write-Output "  - dtop: Navigates to the Desktop folder. Usage: dtop"
    Write-Output "  - ep: Opens the current PowerShell profile in the editor. Usage: ep"

    # Listing and Formatting
    Write-Host "`nListing and Formatting:" -ForegroundColor Green
    Write-Output "  - la: Lists all items in the current directory, formatted as a table. Usage: la"
    Write-Output "  - ll: Lists all items, providing detailed information. Usage: ll"
	
	# Quality of Life Utilities
    Write-Host "`nQuality of Life Utilities:" -ForegroundColor Green
	Write-Output "  - weather: Get Weather information. Usage: weather Location"
	Write-Output "  - qr: Create QR codes. Usage: qrfun url"
	Write-Output "  - googleSearch: Search google for queries. Usage: gs query"
	Write-Output "  - youtubeSearch: Search Youtube for queries. Usage: ys query"
	Write-Output "  - scanfile: Runs SFC scan. Usage: scanfile"
	Write-Output "  - checkhealth: Runs DISM health check. Usage: checkhealth"
	Write-Output "  - scanhealth: Runs DISM health scan. Usage: scanhealth"
	Write-Output "  - restorehealth: Runs DISM health restore. Usage: restorehealth"
	Write-Output "  - ipflush: flushes IP. Usage: ipflush"
	Write-Output "  - shutdown: Shutdown the system. Usage: shutdown"
	Write-Output "  - restart: Restarts the system. Usage: restart"
	Write-Output "  - Edit-Profile: Edits the profile. Usage: Edit-Profile"
	Write-Output "  - cleaner: Cleans temp files. Usage: cleaner"
	Write-Output "  - ipchange: Tries to change IP. Usage: ipchange"

}