## MoveLogs2StorageAccount
Move logs from Azure Log Analytics Workspace to Azure Storage Account in batches

## Download & Run PowerShell Script  

1. Download the Tool

   <a id="historic" href="https://github.com/sreedharande/MoveLogs2StorageAccount/archive/refs/heads/main.zip">Download Tool</a>  
 
2. Extract the folder and open script files either in Visual Studio Code or PowerShell  

   **Note**  
   Currently this script will work from the client's machine, To continue executing this script, run the following command  
   ```
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass  
   ```   
   
3. Enter the parameters  

	$LogAnalyticsWorkspaceName = "MyWorkspace",  
    $LogAnalyticsResourceGroup = "MyRG",  
    $StorageAccountName = "MyStorageAccountName",  
    $StorageAccountResourceGroup = "MyStorageAccountResourceGroup",      
    $TableName = "SentinelHealth",  
    $startperiod = "2021-11-13 00:00:00",  
    $endperiod = "2021-11-15 00:00:00",  
	
4. Script will create container with table name and uploads JSON files

5. Script is designed around the limitations of Azure Log Analytics workspace like the number of records returned to the client to 500,000, and the overall data size for those records to 64 MB. When either of these limits is exceeded, the query fails with a "partial query failure". Exceeding overall data size will generate an exception with the message  
   - Script queries the data for every 12 hours and generates JSON file from Start period to End period