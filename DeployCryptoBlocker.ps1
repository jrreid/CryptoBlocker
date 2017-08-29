<#
.Synopsis
Create and update CryptoLocker detection groups and Templates in FSRM

.Description
Script to create and update CryptoLocker detection groups and Templates in FSRM. 
It downloads a list of known CryptoLocker extensions from a public repositoty and creates file Groups, Templates and Screens in FSRM 

.Parameter GroupName
Specify FSRM File Group Name

.Parameter TemplateName
Specify FSRM File Template Name

.Parameter SkipListPath
Text file containing a list of exclude match strings

.Parameter ActiveTemplate
Boolean: True: Create Active screens that do not allow users to save unauthorized files. False: Passive screening: Allow users to save unauthorized files (use for monitoring)

.Parameter DisableEmail
Do not send an alert email when detection occurs

.Parameter DisableEvent
Do not create an alert event when detection occurs

.Parameter EnableLogging
Enable Transcript logging of session

.Parameter LogFilePath
Where to write log file


.Notes
Last Updated: 2017-08-29
Version     : 1.2

.Example
PS C:\> DeployCryptoBlocker.ps1 

Create File Groups, Screen and Templates. Templates will be passive and an email and event notification will be sent if a match occurs.


.Example
PS C:\> DeployCryptoBlocker.ps1 -NoEmail

Create File Groups, Screen and Templates. Templates will be passive and an event notification will be generated if a match occurs.

.Example
PS C:\> DeployCryptoBlocker.ps1 -Active -NoEvent

Create File Groups, Screen and Templates. Templates will be active and will block file writes that match. An email will be sent if a match occurs.

.Example
PS C:\> DeployCryptoBlocker.ps1 -Active -ProxyHost MyProxy.server.com -ProxyPort 3128 

Create File Groups, Screen and Templates. Templates will be active and will block file writes that match. An email and event will be sent if a match occurs. 
Block list download will use the proxy server specified.


#>
 

[CmdletBinding()]
Param(
    [string] $GroupName = "CryptoBlockerGroup",
	
    [string] $TemplateName = "CryptoBlockerTemplate",
	
	[Parameter(Mandatory=$False,Position=1)]
	[alias('Skip')]
    [string] $SkipListPath = ".\SkipList.txt",
	
	[alias('Active')]
    [switch] $ActiveTemplate,
	
	[alias('NoEmail')]
    [switch] $DisableEmail,
	
	[alias('NoEvent')]
    [switch] $DisableEvent,

	

    [switch] $EnableLogging = $false,
	
    [string] $LogFilePath = ".\Logs\$($env:computername)-$(Get-Date -Format yyyy-MM-dd).txt",
	
	
	[string] $ProxyHost = $false,
	
	[ValidateRange(1,65535)] 
	[int] $ProxyPort = 8080
	
)


################################ USER CONFIGURATION ################################

# Names to use in FSRM
$FileGroupName = $GroupName 
$FileTemplateName = $TemplateName

# Skip List
# If running as a scheduled task give a full path
$SkipList = $SkipListPath

# Logging
# Useful for scheduled tasks
if ($EnableLogging) {
	Start-Transcript -Path $LogFilePath -Append
}

# Proxy
# Uncomment and fill in if your site uses a proxy
if ($ProxyHost){
	$global:PSDefaultParameterValues = @{
		'Invoke-RestMethod:Proxy' = "http://$($ProxyHost):$($ProxyPort)"
		'Invoke-WebRequest:Proxy' = "http://$($ProxyHost):$($ProxyPort)"
		'*:ProxyUseDefaultCredentials' = $true
	}
}

# Screening type
# Active screening: Do not allow users to save unauthorized files
# Passive screening: Allow users to save unauthorized files (use for monitoring)
$fileTemplateActive = $ActiveTemplate


# Write the email options to the temporary file - comment out the entire block if no email notification should be set
$MailTo = "[Admin Email];[Source File Owner Email];[Source Io Owner Email]"

## en
#$Subject = "Unauthorized file from the [Violated File Group] file group detected"
$Subject = "POSSIBLE VIRUS INFECTION DETECTED - [Violated File Group] detected"
$Message = "User [Source Io Owner] attempted to save [Source File Path] to [File Screen Path] on the [Server] server. This file indicates that the file server is in the process of being encrypted by a virus. If you are [Source Io Owner] please shut down any computers you are using IMMEDIATELY and notify IT at <Phone>" 

## de
#$Subject = "Nicht autorisierte Datei erkannt, die mit Dateigruppe [Violated File Group] übereinstimmt"
#$Message = "Das System hat erkannt, dass Benutzer [Source Io Owner] versucht hat, die Datei [Source File Path] unter [File Screen Path] auf Server [Server] zu speichern. Diese Datei weist Übereinstimmungen mit der Dateigruppe [Violated File Group] auf, die auf dem System nicht zulässig ist." 

$Notifications = @()
# Should email notification be sent
if (! $DisableEmail) {
	$Notifications +=  New-FsrmAction -Type Email -Body $Message -MailTo $MailTo -Subject $Subject
}

# Should event notification be created
if (! $DisableEvent) {
	$Notifications +=  New-FsrmAction -Type Event -Body $Message  -EventType Warning
}


################################ USER CONFIGURATION ################################

################################ Functions ################################

Function ConvertFrom-Json20
{
    # Deserializes JSON input into PowerShell object output
    Param (
        [Object] $obj
    )
    Add-Type -AssemblyName System.Web.Extensions
    $serializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
    return ,$serializer.DeserializeObject($obj)
}

Function New-CBArraySplit
{
    <# 
        Takes an array of file extensions and checks if they would make a string >4Kb, 
        if so, turns it into several arrays
    #>
    param(
        $Extensions
    )

    $Extensions = $Extensions | Sort-Object -Unique

    $workingArray = @()
    $WorkingArrayIndex = 1
    $LengthOfStringsInWorkingArray = 0

    # TODO - is the FSRM limit for bytes or characters?
    #        maybe [System.Text.Encoding]::UTF8.GetBytes($_).Count instead?
    #        -> in case extensions have Unicode characters in them
    #        and the character Length is <4Kb but the byte count is >4Kb

    # Take the items from the input array and build up a 
    # temporary workingarray, tracking the length of the items in it and future commas
    $Extensions | ForEach-Object {

        if (($LengthOfStringsInWorkingArray + 1 + $_.Length) -gt 4000) 
        {   
            # Adding this item to the working array (with +1 for a comma)
            # pushes the contents past the 4Kb limit
            # so output the workingArray
            [PSCustomObject]@{
                index = $WorkingArrayIndex
                FileGroupName = "$Script:FileGroupName$WorkingArrayIndex"
                array = $workingArray
            }
            
            # and reset the workingArray and counters
            $workingArray = @($_) # new workingArray with current Extension in it
            $LengthOfStringsInWorkingArray = $_.Length
            $WorkingArrayIndex++

        }
        else #adding this item to the workingArray is fine
        {
            $workingArray += $_
            $LengthOfStringsInWorkingArray += (1 + $_.Length)  #1 for imaginary joining comma
        }
    }

    # The last / only workingArray won't have anything to push it past 4Kb
    # and trigger outputting it, so output that one as well
    [PSCustomObject]@{
        index = ($WorkingArrayIndex)
        FileGroupName = "$Script:FileGroupName$WorkingArrayIndex"
        array = $workingArray
    }
}

################################ Functions ################################

################################ Program code ################################

# Get all drives with shared folders, these drives will get FRSRM protection
#$DrivesContainingShares = @(Get-WmiObject Win32_Share |            # all shares on this computer, filter:
#                            Where-Object { $_.Type -eq 0 } |       # 0 = disk drives (not printers, IPC$, C$ Admin shares)
#                            Select-Object -ExpandProperty Path |    # Shared folder path, e.g. "D:\UserFolders\"
#                            ForEach-Object { 
#                                ([System.IO.DirectoryInfo]$_).Root.Name  # Extract the driveletter, as a string
#                            } | Sort-Object -Unique)               # remove duplicates

$drivesContainingShares = 	@(Get-WmiObject Win32_Share | 
				Select Name,Path,Type | 
				Where-Object { $_.Type -match '0|2147483648' } | 
				Select -ExpandProperty Path | 
				Select -Unique)


if ($drivesContainingShares.Count -eq 0)
{
    Write-Output "`n####"
    Write-Output "No drives containing shares were found. Exiting.."
    exit
}

Write-Output "`n####"
Write-Output "The following shares needing to be protected: $($drivesContainingShares -Join ",")"


# Identify Windows Server version, and install FSRM role
$majorVer = [System.Environment]::OSVersion.Version.Major
$minorVer = [System.Environment]::OSVersion.Version.Minor

Write-Output "`n####"
Write-Output "Checking File Server Resource Manager.."

Import-Module ServerManager

if ($majorVer -ge 6)
{
    $checkFSRM = Get-WindowsFeature -Name FS-Resource-Manager

    if ($minorVer -ge 2 -and $checkFSRM.Installed -ne "True")
    {
        # Server 2012
        Write-Output "`n####"
        Write-Output "FSRM not found.. Installing (2012).."

        $install = Install-WindowsFeature -Name FS-Resource-Manager -IncludeManagementTools
	if ($? -ne $True)
	{
		Write-Output "Install of FSRM failed."
		exit
	}
    }
    elseif ($minorVer -ge 1 -and $checkFSRM.Installed -ne "True")
    {
        # Server 2008 R2
        Write-Output "`n####"
		Write-Output "FSRM not found.. Installing (2008 R2).."
        $install = Add-WindowsFeature FS-FileServer, FS-Resource-Manager
	if ($? -ne $True)
	{
		Write-Output "Install of FSRM failed."
		exit
	}
	
    }
    elseif ($checkFSRM.Installed -ne "True")
    {
        # Server 2008
        Write-Output "`n####"
		Write-Output "FSRM not found.. Installing (2008).."
        $install = &servermanagercmd -Install FS-FileServer FS-Resource-Manager
	if ($? -ne $True)
	{
		Write-Output "Install of FSRM failed."
		exit
	}
    }
}
else
{
    # Assume Server 2003
    Write-Output "`n####"
	Write-Output "Unsupported version of Windows detected! Quitting.."
    return
}

# Download list of CryptoLocker file extensions
Write-Output "`n####"
Write-Output "Dowloading CryptoLocker file extensions list from fsrm.experiant.ca api.."
$Site="https://fsrm.experiant.ca/api/v1/get"
$jsonStr = Invoke-WebRequest -Uri $Site -UseBasicParsing
$monitoredExtensions = @(ConvertFrom-Json20 $jsonStr | ForEach-Object { $_.filters })

# Process SkipList.txt
Write-Output "`n####"
Write-Output "Processing SkipList.."
If (Test-Path $SkipList )
{
    $Exclusions = Get-Content $SkipList  | ForEach-Object { $_.Trim() }
    $monitoredExtensions = $monitoredExtensions | Where-Object { $Exclusions -notcontains $_ }

}
Else 
{
    $emptyFile = @'
#
# Add one filescreen per line that you want to ignore
#
# For example, if *.doc files are being blocked by the list but you want 
# to allow them, simply add a new line in this file that exactly matches 
# the filescreen:
#
# *.doc
#
# The script will check this file every time it runs and remove these 
# entries before applying the list to your FSRM implementation.
#
'@
    Set-Content -Path $SkipList -Value $emptyFile
}

# Split the $monitoredExtensions array into fileGroups of less than 4kb to allow processing by filescrn.exe
$fileGroups = @(New-CBArraySplit $monitoredExtensions)

# Perform these steps for each of the 4KB limit split fileGroups
Write-Output "`n####"
Write-Output "Adding/replacing File Groups.."
ForEach ($group in $fileGroups) {
	Write-Output "`nFile Group [$($group.FileGroupName)] with monitored files from [$($group.array[0])] to [$($group.array[$group.array.GetUpperBound(0)])].."
	Remove-FsrmFileGroup -Name $($group.FileGroupName) -Confirm:$false | Write-Verbose
	New-FsrmFileGroup -Name $($group.FileGroupName) -IncludePattern $($group.array) | Write-Verbose
}

# Create File Screen Template with Notification
Write-Output "`n####"
Write-Output "Adding/replacing [Active:$fileTemplateActive] File Screen Template [$FileTemplateName] with eMail Notification and Event Notification.."
Remove-FsrmFileScreenTemplate -Name $FileTemplateName  -Confirm:$false | Write-Verbose
New-FsrmFileScreenTemplate -Name $FileTemplateName -Active:$fileTemplateActive -IncludeGroup $fileGroups.FileGroupName -Notification $Notifications | Write-Verbose

# Create File Screens for every drive containing shares
# Test for share existence as on File Clusters may be on another node
Write-Output "`n####"
Write-Output "Adding/replacing File Screens.."
$drivesContainingShares | ForEach-Object {
	If (Test-Path $_ ){
		Write-Output "File Screen for [$_] with Source Template [$FileTemplateName].."
		Remove-FsrmFileScreen -Path $_ -Confirm:$false | Write-Verbose
		New-FsrmFileScreen -Path $_ -Template $FileTemplateName | Write-Verbose
	} Else {
		Write-Output "File Screen for [$_] could not be created as the path is invalid"
	}
}

Write-Output "`n####"
Write-Output "Done."
Write-Output "####"

################################ Program code ################################
