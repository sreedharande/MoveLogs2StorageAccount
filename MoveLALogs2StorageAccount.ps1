<#
MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
#>

PARAM (
    [Parameter(Mandatory=$true)] $LogAnalyticsWorkspaceName,
    [Parameter(Mandatory=$true)] $LogAnalyticsResourceGroup, 
    [Parameter(Mandatory=$true)] $StorageAccountName,
    [Parameter(Mandatory=$true)] $StorageAccountResourceGroup,     
    [Parameter(Mandatory=$true)] $TableName,
    [Parameter(Mandatory=$true)] $startperiod,
    [Parameter(Mandatory=$true)] $endperiod,    
    [Parameter(Mandatory=$true)] $HoursInterval       
)

function Write-Log {
    <#
    .DESCRIPTION 
    Write-Log is used to write information to a log file and to the console.
    
    .PARAMETER Severity
    parameter specifies the severity of the log message. Values can be: Information, Warning, or Error. 
    #>

    [CmdletBinding()]
    param(
        [parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Message,
        [string]$LogFileName,
 
        [parameter()]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('Information', 'Warning', 'Error')]
        [string]$Severity = 'Information'
    )
    # Write the message out to the correct channel											  
    switch ($Severity) {
        "Information" { Write-Host $Message -ForegroundColor Green }
        "Warning" { Write-Host $Message -ForegroundColor Yellow }
        "Error" { Write-Host $Message -ForegroundColor Red }
    } 											  
    try {
        [PSCustomObject]@{
            Time     = (Get-Date -f g)
            Message  = $Message
            Severity = $Severity
        } | Export-Csv -Path "$PSScriptRoot\$LogFileName" -Append -NoTypeInformation -Force
    }
    catch {
        Write-Error "An error occurred in Write-Log() method" -ErrorAction SilentlyContinue		
    }    
}

function Get-RequiredModules {
    <#
    .DESCRIPTION 
    Get-Required is used to install and then import a specified PowerShell module.
    
    .PARAMETER Module
    parameter specifices the PowerShell module to install. 
    #>

    [CmdletBinding()]
    param (        
        [parameter(Mandatory = $true)] $Module        
    )
    
    try {
        $installedModule = Get-InstalledModule -Name $Module -ErrorAction SilentlyContinue       

        if ($null -eq $installedModule) {
            Write-Log -Message "The $Module PowerShell module was not found" -LogFileName $LogFileName -Severity Warning
            #check for Admin Privleges
            $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())

            if (-not ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
                #Not an Admin, install to current user            
                Write-Log -Message "Can not install the $Module module. You are not running as Administrator" -LogFileName $LogFileName -Severity Warning
                Write-Log -Message "Installing $Module module to current user Scope" -LogFileName $LogFileName -Severity Warning
                
                Install-Module -Name $Module -Scope CurrentUser -Repository PSGallery -Force -AllowClobber
                Import-Module -Name $Module -Force
            }
            else {
                #Admin, install to all users																		   
                Write-Log -Message "Installing the $Module module to all users" -LogFileName $LogFileName -Severity Warning
                Install-Module -Name $Module -Repository PSGallery -Force -AllowClobber
                Import-Module -Name $Module -Force
            }
        }
        else {
            Write-Log -Message "Checking updates for module $Module" -LogFileName $LogFileName -Severity Information
            $versions = Find-Module $Module -AllVersions
            $latestVersions = ($versions | Measure-Object -Property Version -Maximum).Maximum.ToString()
            $currentVersion = (Get-InstalledModule | Where-Object {$_.Name -eq $Module}).Version.ToString()
            if ($currentVersion -ne $latestVersions) {
                #check for Admin Privleges
                $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())

                if (-not ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
                    #Not an Admin, install to current user            
                    Write-Log -Message "Can not update the $Module module. You are not running as Administrator" -LogFileName $LogFileName -Severity Warning
                    Write-Log -Message "Updating $Module module to current user Scope" -LogFileName $LogFileName -Severity Warning
                    
                    Install-Module -Name $Module -Scope CurrentUser -Repository PSGallery -Force -AllowClobber
                    Import-Module -Name $Module -Force
                }
                else {
                    #Admin, install to all users																		   
                    Write-Log -Message "Updating the $Module module to all users" -LogFileName $LogFileName -Severity Warning
                    Install-Module -Name $Module -Repository PSGallery -Force -AllowClobber
                    Import-Module -Name $Module -Force
                }
            }
            else {
                Write-Log -Message "Importing module $Module" -LogFileName $LogFileName -Severity Information
                Import-Module -Name $Module -Force
            }
        }
        # Install-Module will obtain the module from the gallery and install it on your local machine, making it available for use.
        # Import-Module will bring the module and its functions into your current powershell session, if the module is installed.  
    }
    catch {
        Write-Log -Message "An error occurred in Get-RequiredModules() method" -LogFileName $LogFileName -Severity Error																			
        exit
    }
}

Function QueryLogAnalyticsWithLimits {  
    Param(
    $TableName, 
    $startperiod, 
    $endperiod, 
    $LogAnalyticsWorkspaceId    
    )
    
    $query = "$($TableName)| where TimeGenerated between (todatetime('$startperiod')..todatetime('$endperiod'))"
            
    try {        
        Write-Log -Message "Executing query:$query on Log Analytics table $TableName" -LogFileName $LogFileName -Severity Information                    
        $queryResults = (Invoke-AzOperationalInsightsQuery -WorkspaceId $LogAnalyticsWorkspaceId -Query $query).Results
        
        return $queryResults
    }
    catch {                          
        Write-Log -Message "Performance hit - please reduce row limit" -LogFileName $LogFileName -Severity Error
        Write-Log -Message "Error:$($_)" -LogFileName $LogFileName -Severity Error
    }
}

Function Write-JsonToLocal {
    Param (
        [Parameter(Mandatory=$true)] $LogAnalyticsQueryResults,
        [Parameter(Mandatory=$true)] $QueryStartPeriod,
        [Parameter(Mandatory=$true)] $QueryEndPeriod
    )    
    $QueryStartPeriod = Get-Date $QueryStartPeriod -Format yyyyMMdd_HHmmss
    $QueryEndPeriod = Get-Date $QueryEndPeriod -Format yyyyMMdd_HHmmss

    $BlobFileName = '{0}_{1}_{2}.json' -f $TableName, $QueryStartPeriod, $QueryEndPeriod 
    $BlobFilePath = "$PSScriptRoot\$BlobFileName"
    
    $LogAnalyticsQueryResults | Set-Content $BlobFilePath
    
    return $BlobFilePath
}

Function Write-AzureStorageAccountContainer {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)] $StorageAcctContext,
        [Parameter(Mandatory=$true)] $StorageBlob
    )

    $IsContainerExists = Get-AzStorageContainer -Name $TableName.ToLower() -Context $StorageAcctContext -erroraction 'silentlycontinue' 
    if($null -eq $IsContainerExists) {
        New-AzStorageContainer -Name $TableName.ToLower() -Context $StorageAcctContext
    }

    $UploadFile = @{
        Context = $StorageAcctContext;    
        Container = $TableName.ToLower();    
        File = $StorageBlob;    
    }
    
    try {
        $UploadStatus = Set-AzStorageBlobContent @UploadFile
    }
    catch [Exception] { 
		Write-warning "Error Message: `n$_ "		
	}	
    
    return $UploadStatus
}

# Check powershell version, needs to be 5 or higher
if ($host.Version.Major -lt 5) {
    Write-Log "Supported PowerShell version for this script is 5 or above" -LogFileName $LogFileName -Severity Error    
    exit
}

Get-RequiredModules("Az.Resources")
Get-RequiredModules("Az.OperationalInsights")
Get-RequiredModules("Az.Storage")


$TimeStamp = Get-Date -Format yyyyMMdd_HHmmss
$LogFileName = '{0}_{1}.csv' -f "HistoricDataMigration", $TimeStamp

Write-Host "`r`nIf not logged in to Azure already, you will now be asked to log in to your Azure environment. `nFor this script to work correctly, you need to provide credentials `nAzure Log Analytics Workspace Read Permissions `nAzure Data Explorer Database User Permission. " -BackgroundColor Blue

Read-Host -Prompt "Press enter to continue or CTRL+C to quit the script"

$context = Get-AzContext

if(!$context){  
    Connect-AzAccount
    $context = Get-AzContext
}

try {
    $WorkspaceObject = Get-AzOperationalInsightsWorkspace -Name $LogAnalyticsWorkspaceName -ResourceGroupName $LogAnalyticsResourceGroup -DefaultProfile $context 
    $LogAnalyticsLocation = $WorkspaceObject.Location
    $LogAnalyticsWorkspaceId = $WorkspaceObject.CustomerId
    
    Write-Log -Message "Workspace named $LogAnalyticsWorkspaceName in region $LogAnalyticsLocation exists." -LogFileName $LogFileName -Severity Information
} 
catch {    
    Write-Log -Message "$LogAnalyticsWorkspaceName not found" -LogFileName $LogFileName -Severity Error
}

#Check Storage Account Exists or not
$isStorageAccountExists = Get-AzStorageAccount -ResourceGroupName $StorageAccountResourceGroup `
                                                  -Name $StorageAccountName
if($null -eq $isStorageAccountExists) {
    New-AzStorageAccount -ResourceGroupName $StorageAccountResourceGroup `
                            -Name $StorageAccountName `
                            -Location $LogAnalyticsLocation `
                            -SkuName Standard_RAGRS `
                            -Kind StorageV2 `
                            -Verbose
}
else {
    $StorageAccountKeys = Get-AzStorageAccountKey -ResourceGroupName $StorageAccountResourceGroup `
                                                       -Name $StorageAccountName

    $StorageAccountContext = New-AzStorageContext -StorageAccountName $StorageAccountName -StorageAccountKey $StorageAccountKeys[0].value
}

$transferStartTime = Get-Date
$actualStartperiod = $startperiod
DO {    
    Write-Log -Message "Moving historic Data from $TableName from $startperiod to $endperiod" -LogFileName $LogFileName -Severity Information
    try {
        $startperiod = Get-Date $startperiod
        $endperiod = Get-Date $endperiod
                
        $LaLogs = QueryLogAnalyticsWithLimits  -TableName $TableName `
            -startperiod $startperiod `
            -endperiod $endperiod `
            -LogAnalyticsWorkspaceId $LogAnalyticsWorkspaceId
                
        $ResultsArray = @() 
        foreach ($rowData in $LaLogs) {            
            $ResultsArray += $rowData | ConvertTo-Json -Depth 100
        }       
        
        $JoinedRows = $ResultsArray -join "`r`n"
        $LogAnalyticsQueryResults = $JoinedRows               
        
        $LocalBlobFile = Write-JsonToLocal -LogAnalyticsQueryResults $LogAnalyticsQueryResults -QueryStartPeriod $startperiod -QueryEndPeriod $endperiod
        $BlobUploadStatus = Write-AzureStorageAccountContainer -StorageAcctContext $StorageAccountContext -StorageBlob $LocalBlobFile
        
        if ($BlobUploadStatus) {
            Remove-Item $LocalBlobFile -Force
            $startperiod = $startperiod.AddHours($HoursInterval)
        }             
    }
    catch {        
        Write-Log -Message "Error in historic data transfer from $TableName between $startperiod to $endperiod" -LogFileName $LogFileName -Severity Error
        Write-Log -Message "Error : $($_)" -LogFileName $LogFileName -Severity Error        
    }   
            
} While ($startperiod -lt $endperiod)

$transferEndTime = Get-Date
$totalTransferTime = $transferEndTime - $transferStartTime

Write-Log -Message "Success!!! Date between $actualStartperiod and $endperiod uploaded to $StorageAccountName; Transfer Start Time:$transferStartTime; Transfer End Time:$transferEndTime; Total Transfer time:$totalTransferTime" -LogFileName $LogFileName -Severity Information