$location = "japan east"
$SubscriptionId = (az account show | convertfrom-json).id
$tenantId = (az account show | convertfrom-json).tenantid
$Id = "010"
$ResourceDefaultNm = "jp.rbs.wak-any"
$ResourceDefaultNmhyphen = "jp-rbs-wak-any"
$ResourceBaseNm = "$ResourceDefaultNm-$Id"
$ResourceBaseNmhyphen = "$ResourceDefaultNmhyphen-$Id"
$RgNm = "$ResourceBaseNm-rg"
$RgCommonNm = "$ResourceDefaultNm-rg"
$FunctionSANm = "jprbswakany${Id}fs02"
$PublicSANm = "jprbswakany${Id}as02"
$PublicSAURL = "https://$PublicSANm.z11.web.core.windows.net"
$SQLSrv = "$ResourceBaseNmhyphen-sql02"
$SQLDb = "$ResourceBaseNmhyphen-sqldb02"
$SQLAdminGroup = "d9957e33-fe33-4cb3-adff-c55db4158bfc"
$SysAdminObjId = "da7a8c9b-541a-47c1-963d-d912b3e790d6"
$SQLConStringNm = "$ResourceDefaultNmhyphen-$id-SQLConnString"
$VNetNm = "$ResourceDefaultNm-vnet-spoke"
$SubnetNm = "snet-pep"
$SubnetIntegNm = "snet-vnetiteg"
$RtSpoke2hub = "$ResourceDefaultNm-rt-spoke2hub"
$RtVnet2hub = "$ResourceDefaultNm-rt-VnetInteg2hub"
$VNetIntegSubnetid=(az network vnet subnet show `
  --resource-group $RgCommonNm `
  --vnet-name $VNetNm `
  --name $SubnetIntegNm `
  --query id `
  --output tsv)
$AppInsightsNm = "$ResourceBaseNmhyphen-appi"
$LogAnalyticsNm = "$ResourceBaseNmhyphen-log"
$KeyVaultCommonNm = "$ResourceDefaultNmhyphen-kv2"
$KeyVaultNm = "jprbswakany${Id}-kv02"
$KeyVaultGraphSecret = "$ResourceBaseNmhyphen-GraphAPI"
$KeyVaultGraphSecretValue = "null"
$OperationUser = (az account show | convertfrom-json).user.name
$OperationUser
$AppPlan = "$ResourceDefaultNmhyphen-$Id-asp02"
$Wa = "$ResourceDefaultNmhyphen-$Id-wa02"
$WaAR = "$ResourceDefaultNmhyphen-$Id-arwa02"
$Fa = "$ResourceDefaultNmhyphen-$Id-fa02"
$FaAR = "$ResourceDefaultNmhyphen-$Id-arfa02"
$RaURL = "https://www.rbsdevtest2.com"
$CustomerTenant = "97cd0e82-f22b-45c0-bd8e-47f2ce63d9a5"
$CustomerAppId = "<顧客テナントに登録した AppId>"
$RATenantId = "https://robinson2025b.onmicrosoft.com"
$appConfigName = "$ResourceDefaultNmhyphen-appConfig2"
$N = 32; $Chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'; $CsvSecret = -join ((1..$N) | % { Get-Random -InputObject $Chars.ToCharArray() })
Write-Output "Generated Csv Secret: $CsvSecret"
$Pw = 12
$Digits = '0123456789'
$Lower = 'abcdefghijklmnopqrstuvwxyz'
$Upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
$Symbols = '!?#%'
$AllChars = $Digits + $Lower + $Upper + $Symbols
$SqlPassword = -join @(
    Get-Random -InputObject $Digits.ToCharArray()
    Get-Random -InputObject $Lower.ToCharArray()
    Get-Random -InputObject $Upper.ToCharArray()
    Get-Random -InputObject $Symbols.ToCharArray()
    (1..($Pw - 4) | ForEach-Object { Get-Random -InputObject $AllChars.ToCharArray() })
)
Write-Output "Generated SQL Password: $SqlPassword"
$WaDiag = "$Wa-diag"
$FaDiag = "$Fa-diag"
$AppPlanDiag = "$AppPlan-diag"
$KeyVaultNmDiag = "$KeyVaultNm-diag"
$SQLDbDiag = "$SQLDb-diag"
$omakase = "omakase-room@robinson2025b.onmicrosoft.com"
$FunctionSADiag = "$FunctionSANm-diag"
$FunctionSAblobDiag = "$FunctionSANm-blob-diag"
$FunctionSAqueueDiag = "$FunctionSANm-queue-diag"
$FunctionSAtableDiag = "$FunctionSANm-table-diag"
$FunctionSAfileDiag = "$FunctionSANm-file-diag"
$omakase = "omakase-room@robinson2025b.onmicrosoft.com"
$SystemUserId = "y.wakita@robinson2025b.onmicrosoft.com"
$result = az group show --name $RgNm
($result | convertfrom-json).properties
$result = az monitor log-analytics workspace create `
  --name $LogAnalyticsNm `
  --resource-group $RgNm `
  --location $location
($result | convertfrom-json)
$workspaceid = (az monitor log-analytics workspace show --resource-group $RgNm --name $LogAnalyticsNm | ConvertFrom-Json).id
$result = az sql server create --location $location `
  -g $RgNm `
  -n $SQLSrv `
  -u sqladmin `
  -p "$SqlPassword" `
  --minimal-tls-version 1.2
($result | convertfrom-json).state
$result = az sql db create -g $RgNm -s $SQLSrv -n $SQLDb `
 --backup-storage-redundancy GeoZone `
 --capacity 4 `
 --min-capacity 0.5 `
 --compute-model Serverless `
 --tier "GeneralPurpose" `
 --family "Gen5" `
 --service-level-objective "GP_S_Gen5_4" `
 -z
($result | convertfrom-json).status
$result = az sql server audit-policy update --log-analytics-target-state Enabled `
  --log-analytics-workspace-resource-id $workspaceid `
  --name $SQLSrv `
  --resource-group $RgNm `
  --state Enabled
($result | convertfrom-json)
$SQLConString = "Server=$SQLSrv.database.windows.net; Authentication=Active Directory Managed Identity; Database=$SQLDb"
(az appservice plan show --resource-group $RgNm --name $AppPlan | ConvertFrom-Json) | Select-Object name, @{Name='zoneRedundant'; Expression={$_.properties.zoneRedundant}}, @{Name='skuName'; Expression={$_.sku.name}} | Format-Table -AutoSize
(az webapp show --resource-group $RgNm --name $Wa | ConvertFrom-Json) | Select-Object name, httpsonly, publicnetworkaccess, @{Name='runtime'; Expression={$_.siteConfig.netFrameworkVersion}} | Format-Table -AutoSize
$result = az webapp config set --resource-group $RgNm `
  --name $Wa `
  --use-32bit-worker-process false `
  --always-on true `
  --ftps-state Disabled `
  --http20-enabled false `
  --min-tls-version "1.2"
($result | ConvertFrom-Json) | Select-Object name, use32bitworkerprocess, alwaysOn, ftpsState, http20Enabled, minTlsVersion, netFrameworkVersion
(az resource show --resource-group $RgNm --name ftp --namespace Microsoft.Web --resource-type basicPublishingCredentialsPolicies --parent sites/$Wa | ConvertFrom-Json) | Select-Object @{Name='FtpAllow'; Expression={$_.properties.allow}} | Format-Table -AutoSize
(az resource show --resource-group $RgNm --name scm --namespace Microsoft.Web --resource-type basicPublishingCredentialsPolicies --parent sites/$Wa | ConvertFrom-Json) | Select-Object @{Name='ScmAllow'; Expression={$_.properties.allow}} | Format-Table -AutoSize
$result = az webapp identity show --resource-group $RgNm --name $Wa
$WaSystemId = ($result | ConvertFrom-Json).principalId
$KeyVaultCommonScope = (az keyvault show -g $RgCommonNm --name $KeyVaultCommonNm | ConvertFrom-Json).id
$result=az role assignment create `
  --role 4633458b-17de-408a-b874-0445c86b69e6 `
  --assignee-object-id $WaSystemId `
  --assignee-principal-type ServicePrincipal `
  --scope $KeyVaultCommonScope
($result | ConvertFrom-Json).createdOn
$KeyVaultScope = (az keyvault show -g $RgNm --name $KeyVaultNm | ConvertFrom-Json).id
$result=az role assignment create `
  --role f25e0fa2-a7c8-4377-a976-54943a77a395 `
  --assignee $OperationUser `
  --scope $KeyVaultScope
($result | ConvertFrom-Json).createdOn
$result=az role assignment create `
  --role 00482a5a-887f-4fb3-b363-3b7fe8e74483 `
  --assignee $OperationUser `
  --scope $KeyVaultScope
($result | ConvertFrom-Json).createdOn
$result=az role assignment create `
  --role db79e9a7-68ee-4b58-9aeb-b90e7c24fcba `
  --assignee $OperationUser `
  --scope $KeyVaultScope
($result | ConvertFrom-Json).createdOn
$result=az role assignment create `
  --role 4633458b-17de-408a-b874-0445c86b69e6 `
  --assignee-object-id $WaSystemId `
  --assignee-principal-type ServicePrincipal `
  --scope $KeyVaultScope
($result | ConvertFrom-Json).createdOn
$Kvid=$(az keyvault list `
 --resource-group $RgNm `
 --query '[].[id]' `
 --output tsv)
 $result=az network private-endpoint create `
 --name "$KeyVaultNm-pep" `
 --resource-group $RgCommonNm `
 --vnet-name $VNetNm --subnet $SubnetNm `
 --private-connection-resource-id $Kvid `
 --group-id "vault" `
 --connection-name "$KeyVaultNm-pep-$SubscriptionId"
($result | convertfrom-json).customDnsConfigs
$KvPrivateIp = ($result | convertfrom-json).customDnsConfigs[0].ipAddresses
az network private-dns record-set a add-record `
 -g $RgCommonNm `
 -z privatelink.vaultcore.azure.net `
 -n "$KeyVaultNm" `
 -a $KvPrivateIp
 az network private-dns record-set a update `
 -g $RgCommonNm `
 -z privatelink.vaultcore.azure.net `
 -n "$KeyVaultNm" `
 --set ttl=10
$result=(az keyvault secret set --name $SQLConStringNm `
  --vault-name $KeyVaultNm `
  --value $SQLConString)
$result=(az keyvault secret set --name $KeyVaultGraphSecret `
  --vault-name $KeyVaultNm `
  --value "$KeyVaultGraphSecretValue")
$SQLConValue = (az keyvault secret list --vault-name $KeyVaultNm | ConvertFrom-Json | where {$_.name -eq $SQLConStringNm}).id
az keyvault update `
  --name $KeyVaultNm `
  --resource-group $RgNm `
  --public-network-access Disabled
$appiconString = (az monitor app-insights component show --resource-group $RgNm --app $AppInsightsNm | convertFrom-Json).connectionString
az webapp config appsettings set --name $Wa `
  --resource-group $RgNm `
  --settings APPLICATIONINSIGHTS_CONNECTION_STRING=$appiconString ApplicationInsightsAgent_EXTENSION_VERSION=~2 XDT_MicrosoftApplicationInsights_Mode=default
az webapp config appsettings list --name $Wa --resource-group $RgNm | ConvertFrom-Json
az webapp config connection-string set --resource-group $RgNm `
  --name $Wa `
  --connection-string-type "SQLServer" `
  --settings "ReserveAnyManagementContext=""@Microsoft.KeyVault(SecretUri=$SQLConValue)""" `
  --slot-settings "ReserveAnyManagementContext=""@Microsoft.KeyVault(SecretUri=$SQLConValue)"""
$result=az ad app create --display-name $WaAR `
  --web-home-page-url "https://$Wa.azurewebsites.net"
$WaAppId=(az ad app list --display-name $WaAR | ConvertFrom-Json).appId
az ad app update --id $WaAppId --web-redirect-uris "$RaURL/.auth/login/aad/callback" "$RaURL/$Id/admin/.auth/login/aad/callback" "https://$Wa.azurewebsites.net/.auth/login/aad/callback"
az ad app update --id $WaAppId `
  --enable-access-token-issuance true `
  --enable-id-token-issuance true `
  --sign-in-audience AzureADMultipleOrgs
$result=(az ad app credential reset --id  $WaAppId --display-name "$Wa-secret" --years 2 --append)
$WaAppSecret=($result | ConvertFrom-Json).password
Write-Output $WaAppSecret
az ad app permission add --id $WaAppId --api 00000003-0000-0000-c000-000000000000 `
--api-permissions "e1fe6dd8-ba31-4d61-89e7-88639da4683d=Scope"
az ad app update --id $WaAppId `
  --identifier-uris "api://$WaAppId"
$apiScopeId = [guid]::NewGuid().Guid
$apiScopeJson = @{
    requestedAccessTokenVersion = 2
    oauth2PermissionScopes      = @(
        @{
            adminConsentDescription = "Allow the application to access $Wa on behalf of the signed-in user."
            adminConsentDisplayName = "Access $Wa"
            id                      = "$apiScopeId"
            isEnabled               = $true
            type                    = "User"
            userConsentDescription  = "Allow the application to access $Wa on your behalf."
            userConsentDisplayName  = "Access $Wa"
            value                   = "user_impersonation"
        }
    )
} | ConvertTo-Json -d 4 -Compress
$apiUpdateBody = $apiScopeJson | ConvertTo-Json -d 4
az ad app update --id $WaAppId --set api=$apiUpdateBody
$spId = az ad sp create `
  --id $WaAppId `
  --query id `
  --output tsv
az webapp config appsettings set --name $Wa `
  --resource-group $RgNm `
  --settings "BasePath=/$Id/admin/"
az webapp config appsettings set --name $Wa `
  --resource-group $RgNm `
  --slot-settings "MICROSOFT_PROVIDER_AUTHENTICATION_SECRET=$WaAppSecret"
az webapp config appsettings set --name $Wa `
  --resource-group $RgNm `
  --slot-settings "TrialEndDay=@Microsoft.AppConfiguration(Endpoint=https://jp-rbs-wak-any-appConfig.azconfig.io; Key=${Id}:TrialEndDay)"
az webapp config appsettings set --name $Wa `
  --resource-group $RgNm `
  --slot-settings "TrialStartDay=@Microsoft.AppConfiguration(Endpoint=https://jp-rbs-wak-any-appConfig.azconfig.io; Key=${Id}:TrialStartDay)"
az webapp config appsettings set --name $Wa `
  --resource-group $RgNm `
  --settings "WEBSITE_AUTH_AAD_ALLOWED_TENANTS=$tenantId"
az webapp config appsettings set --name $Wa `
  --resource-group $RgNm `
  --settings "WEBSITE_DNS_SERVER=168.63.129.16"
az webapp config appsettings set --name $Wa `
  --resource-group $RgNm `
  --settings "WEBSITE_TIME_ZONE=Tokyo Standard Time"
az webapp config appsettings list --name $Wa `
  --resource-group $RgNm `
 | ConvertFrom-Json
az webapp auth config-version upgrade --name $Wa --resource-group $RgNm
az extension add --name authV2
az webapp auth update --name $Wa `
  --resource-group $RgNm `
  --redirect-provider "azureactivedirectory" `
  --action RedirectToLoginPage `
  --enabled true `
  --enable-token-store true `
  --set identityProviders.azureActiveDirectory.isAutoProvisioned=$True
az webapp auth update --name $Wa `
  --resource-group $RgNm `
  --proxy-convention Custom `
  --proxy-custom-host-header "X-Original-Host"
az webapp auth microsoft update --name $Wa `
  --resource-group $RgNm `
  --client-id $WaAppId `
  --client-secret "$WaAppSecret" `
  --issuer "https://login.microsoftonline.com/common/v2.0" `
  --allowed-audiences "api://$WaAppId" `
  --yes
az webapp auth update --name $Wa `
  --resource-group $RgNm `
  --set httpSettings.routes.apiPrefix="/$Id/admin/.auth"
az webapp auth update --name $Wa `
  --resource-group $RgNm `
  --set login.routes.logoutEndpoint="/.auth/logout"
$WaARAppId = (az ad app list --display-name $WaAR | ConvertFrom-Json)[0].appId
$WaAuthSettingsId = "/subscriptions/$SubscriptionId/resourceGroups/$RgNm/providers/Microsoft.Web/sites/$Wa/config/authsettingsV2"
az resource update `
  --ids $WaAuthSettingsId `
  --set properties.identityProviders.azureActiveDirectory.registration.clientAppId=$WaARAppId `
        properties.identityProviders.azureActiveDirectory.validation.defaultAuthorizationPolicy.allowedApplications[0]=$WaARAppId `
        properties.identityProviders.azureActiveDirectory.validation.defaultAuthorizationPolicy.allowedApplications[1]=$CustomerAppId
$result = az webapp config set --resource-group $RgNm `
  --name $Wa `
  --use-32bit-worker-process false `
  --always-on true `
  --ftps-state Disabled `
  --http20-enabled false `
  --min-tls-version "1.2" `
  --runtime "dotnet:8" `
  --slot "stg"
($result | ConvertFrom-Json) | Select-Object name, use32bitworkerprocess, alwaysOn, ftpsState, http20Enabled, minTlsVersion, netFrameworkVersion
(az resource show --resource-group $RgNm --name ftp --namespace Microsoft.Web --resource-type basicPublishingCredentialsPolicies --parent sites/$Wa/slots/stg | ConvertFrom-Json) | Select-Object @{Name='FtpAllow'; Expression={$_.properties.allow}} | Format-Table -AutoSize
(az resource show --resource-group $RgNm --name scm --namespace Microsoft.Web --resource-type basicPublishingCredentialsPolicies --parent sites/$Wa/slots/stg | ConvertFrom-Json) | Select-Object @{Name='ScmAllow'; Expression={$_.properties.allow}} | Format-Table -AutoSize
$result = az webapp identity show --resource-group $RgNm --name $Wa --slot "stg"
$WaSystemStgId = ($result | ConvertFrom-Json).principalId
az webapp config appsettings set --name $Wa --slot stg `
  --resource-group $RgNm `
  --settings "BasePath=/$Id/admin/"
az webapp config appsettings set --name $Wa --slot stg `
  --resource-group $RgNm `
  --settings "WEBSITE_AUTH_AAD_ALLOWED_TENANTS=$tenantId"
az webapp config appsettings set --name $Wa --slot stg `
  --resource-group $RgNm `
  --settings "WEBSITE_DNS_SERVER=168.63.129.16"
az webapp config appsettings set --name $Wa --slot stg `
  --resource-group $RgNm `
  --settings "WEBSITE_TIME_ZONE=Tokyo Standard Time"
az webapp config appsettings list --name $Wa --slot stg `
  --resource-group $RgNm `
 | ConvertFrom-Json
$KeyVaultCommonScope = (az keyvault show -g $RgCommonNm --name $KeyVaultCommonNm | ConvertFrom-Json).id
$result=az role assignment create `
  --role 4633458b-17de-408a-b874-0445c86b69e6 `
  --assignee-object-id $WaSystemStgId `
  --assignee-principal-type ServicePrincipal `
  --scope $KeyVaultCommonScope
($result | ConvertFrom-Json).createdOn
$result=az role assignment create `
  --role 4633458b-17de-408a-b874-0445c86b69e6 `
  --assignee-object-id $WaSystemStgId `
  --assignee-principal-type ServicePrincipal `
  --scope $KeyVaultScope
($result | ConvertFrom-Json).createdOn
az webapp config appsettings set --name $Wa `
  --resource-group $RgNm `
  --settings APPLICATIONINSIGHTS_CONNECTION_STRING=$appiconString ApplicationInsightsAgent_EXTENSION_VERSION=~2 XDT_MicrosoftApplicationInsights_Mode=default `
  --slot stg
az webapp config appsettings list --name $Wa --slot stg --resource-group $RgNm | ConvertFrom-Json
az webapp config connection-string set --resource-group $RgNm `
  --name $Wa --slot stg `
  --connection-string-type "SQLServer" `
  --settings "ReserveAnyManagementContext=""@Microsoft.KeyVault(SecretUri=$SQLConValue)""" `
  --slot-settings "ReserveAnyManagementContext=""@Microsoft.KeyVault(SecretUri=$SQLConValue)"""
(az webapp config show --resource-group $RgNm --name $Fa | ConvertFrom-Json) | Select-Object name, use32bitworkerprocess, alwaysOn, ftpsState, http20Enabled, minTlsVersion, netFrameworkVersion
(az resource show --resource-group $RgNm --name ftp --namespace Microsoft.Web --resource-type basicPublishingCredentialsPolicies --parent sites/$Fa | ConvertFrom-Json) | Select-Object @{Name='FtpAllow'; Expression={$_.properties.allow}} | Format-Table -AutoSize
(az resource show --resource-group $RgNm --name scm --namespace Microsoft.Web --resource-type basicPublishingCredentialsPolicies --parent sites/$Fa | ConvertFrom-Json) | Select-Object @{Name='ScmAllow'; Expression={$_.properties.allow}} | Format-Table -AutoSize
$result = az functionapp identity show --resource-group $RgNm --name $Fa
$FaSystemId = ($result | ConvertFrom-Json).principalId
$KeyVaultCommonScope = (az keyvault show -g $RgCommonNm --name $KeyVaultCommonNm | ConvertFrom-Json).id
$result=az role assignment create `
  --role 4633458b-17de-408a-b874-0445c86b69e6 `
  --assignee-object-id $FaSystemId `
  --assignee-principal-type ServicePrincipal `
  --scope $KeyVaultCommonScope
($result | ConvertFrom-Json).createdOn
$result=az role assignment create `
  --role 4633458b-17de-408a-b874-0445c86b69e6 `
  --assignee-object-id $FaSystemId `
  --assignee-principal-type ServicePrincipal `
  --scope $KeyVaultScope
($result | ConvertFrom-Json).createdOn
az functionapp config appsettings set --name $Fa `
  --resource-group $RgNm `
  --settings APPLICATIONINSIGHTS_CONNECTION_STRING=$appiconString ApplicationInsightsAgent_EXTENSION_VERSION=~2 XDT_MicrosoftApplicationInsights_Mode=default
az functionapp config appsettings list --name $Fa --resource-group $RgNm | ConvertFrom-Json
az webapp config connection-string set --resource-group $RgNm `
  --name $Fa `
  --connection-string-type "SQLServer" `
  --settings "ReserveAnyManagementContext=""$SQLConString""" `
  --slot-settings "ReserveAnyManagementContext=""$SQLConString"""
$result=az ad app create --display-name $FaAR `
  --web-home-page-url "https://$Fa.azurewebsites.net"
$FaAppId=(az ad app list --display-name $FaAR | ConvertFrom-Json).appId
az ad app update --id $FaAppId --web-redirect-uris  "$RaURL/.auth/login/aad/callback" "$RaURL/$Id/api/.auth/login/aad/callback" "https://$Fa.azurewebsites.net/$Id/api/.auth/login/aad/callback"
$FaobjectId = (az ad app show --id $FaAppId | ConvertFrom-Json).Id
az rest `
  --method "patch" `
  --uri "https://graph.microsoft.com/v1.0/applications/$FaobjectId" `
  --headers "{'Content-Type': 'application/json'}" `
  --body "{'spa': {'redirectUris': [ 'https://localhost:3000', 'http://localhost:3000' ]}}"
az ad app update --id $FaAppId `
  --enable-access-token-issuance true `
  --enable-id-token-issuance true `
  --sign-in-audience AzureADMultipleOrgs
$result=(az ad app credential reset --id  $FaAppId --display-name "$Fa-secret" --years 2 --append)
$FaAppSecret=($result | ConvertFrom-Json).password
Write-Output $FaAppSecret
az ad app permission add --id $FaAppId --api 00000003-0000-0000-c000-000000000000 `
--api-permissions "e1fe6dd8-ba31-4d61-89e7-88639da4683d=Scope"
az ad app update --id $FaAppId `
  --identifier-uris "$RATenantId/$FaAppId"
$apiScopeId = [guid]::NewGuid().Guid
$apiScopeJson = @{
    requestedAccessTokenVersion = 2
    oauth2PermissionScopes      = @(
        @{
            adminConsentDescription = "Allow the application to access $Fa on behalf of the signed-in user."
            adminConsentDisplayName = "Access $Fa"
            id                      = "$apiScopeId"
            isEnabled               = $true
            type                    = "User"
            userConsentDescription  = "Allow the application to access $Fa on your behalf."
            userConsentDisplayName  = "Access $Fa"
            value                   = "user_impersonation"
        }
    )
} | ConvertTo-Json -d 4 -Compress
$apiUpdateBody = $apiScopeJson | ConvertTo-Json -d 4
az ad app update --id $FaAppId --set api=$apiUpdateBody
$objectId = (az ad app show --id $FaAppId | ConvertFrom-Json).id
$apiScopeId = [guid]::NewGuid().Guid
$appRoles = "[{`"value`": `"FunctionApp.Read`",`"displayName`": `"FunctionApp.Read`",`"description`": `"FunctionApp.Read`",`"id`": `"$apiScopeId`",`"allowedMemberTypes`": [`"Application`",`"User`"]}]"
$json = $appRoles | ConvertTo-Json -Depth 10 -Compress
az ad app update --id $FaAppId --app-roles $json
az ad app show --id $FaAppId --query appRoles
$spId = az ad sp create `
  --id $FaAppId `
  --query id `
  --output tsv
az functionapp config appsettings set --name $Fa `
  --resource-group $RgNm `
  --settings "AddinAppId=$AddinAppId"
az functionapp config appsettings set --name $Fa `
  --resource-group $RgNm `
  --settings "AddinSiteURL=https://$PublicSANm.z11.web.core.windows.net"
az functionapp config appsettings set --name $Fa `
  --resource-group $RgNm `
  --slot-settings "AllFeatureFlg=@Microsoft.AppConfiguration(Endpoint=https://jp-rbs-wak-any-appConfig.azconfig.io; Key=${Id}:AllFeatureFlg)"
az functionapp config appsettings set --name $Fa `
  --resource-group $RgNm `
  --settings "AzureFunctionsJobHost__extensions__http__routePrefix=$Id/api/"
az functionapp config appsettings set --name $Fa `
  --resource-group $RgNm `
  --settings "AzureFunctionsJobHost__functionTimeout=02:00:00"
az functionapp config appsettings set --name $Fa `
  --resource-group $RgNm `
  --settings "BlobLocksContainerName=reservation-bloblocks"
az functionapp config appsettings set --name $Fa `
  --resource-group $RgNm `
  --settings "CheckConsistencyQueueName=queue-checkconsistencyqueue-items"
az functionapp config appsettings set --name $Fa `
  --resource-group $RgNm `
  --slot-settings "ConditionsReservationFeatureFlg=@Microsoft.AppConfiguration(Endpoint=https://jp-rbs-wak-any-appConfig.azconfig.io; Key=${Id}:ConditionsReservationFeatureFlg)"
az functionapp config appsettings set --name $Fa `
  --resource-group $RgNm `
  --settings "CsvEncryptionSecret=$CsvSecret"
az functionapp config appsettings set --name $Fa `
  --resource-group $RgNm `
  --slot-settings "DPFeatureFlg=@Microsoft.AppConfiguration(Endpoint=https://jp-rbs-wak-any-appConfig.azconfig.io; Key=${Id}:DPFeatureFlg)"
az functionapp config appsettings set --name $Fa `
  --resource-group $RgNm `
  --slot-settings "DurableTaskHubName=RANotificationTaskHub"
az functionapp config appsettings set --name $Fa `
  --resource-group $RgNm `
  --slot-settings "FunctionsLifecycleNotifyClientKey=アプリデプロイ後に更新"
az functionapp config appsettings set --name $Fa `
  --resource-group $RgNm `
  --slot-settings "FunctionsNotifyClientKey=アプリデプロイ後に更新"
az functionapp config appsettings set --name $Fa `
  --resource-group $RgNm `
  --slot-settings "FunctionSiteURL=$RaURL/$id/api"
az functionapp config appsettings set --name $Fa `
  --resource-group $RgNm `
  --settings "GraphConnectionInfo:ClientID=$CustomerAppId"
az functionapp config appsettings set --name $Fa `
  --resource-group $RgNm `
  --settings "GraphConnectionInfo:ClientSecret=""@Microsoft.KeyVault(SecretUri=https://$KeyVaultNm.vault.azure.net/secrets/jp-rbs-wak-any-${Id}-GraphAPI)"""
az functionapp config appsettings set --name $Fa `
  --resource-group $RgNm `
  --settings "GraphConnectionInfo:TenantID=$CustomerTenant"
az functionapp config appsettings set --name $Fa `
  --resource-group $RgNm `
  --settings "HandleNotificationQueueName=queue-handlenotification-items"
az functionapp config appsettings set --name $Fa `
  --resource-group $RgNm `
  --slot-settings "HotellingCSVFeatureFlg=@Microsoft.AppConfiguration(Endpoint=https://jp-rbs-wak-any-appConfig.azconfig.io; Key=${Id}:HotellingCSVFeatureFlg)"""
az functionapp config appsettings set --name $Fa `
  --resource-group $RgNm `
  --slot-settings "HotellingFeatureFlg=@Microsoft.AppConfiguration(Endpoint=https://jp-rbs-wak-any-appConfig.azconfig.io; Key=${Id}:HotellingFeatureFlg)"""
az functionapp config appsettings set --name $Fa `
  --resource-group $RgNm `
  --slot-settings "HotellingLabelAllowIP=*"
az functionapp config appsettings set --name $Fa `
  --resource-group $RgNm `
  --slot-settings "MICROSOFT_PROVIDER_AUTHENTICATION_SECRET=$FaAppSecret"
az functionapp config appsettings set --name $Fa `
  --resource-group $RgNm `
  --slot-settings "OmakaseResourceMail=$omakase"
az functionapp config appsettings set --name $Fa `
  --resource-group $RgNm `
  --slot-settings "RegisterSubscriptionRunMode=ValidateAndRegister"
az functionapp config appsettings set --name $Fa `
  --resource-group $RgNm `
  --settings "ScheduleCheckNotificationEntityTimeouts=0 0 * * * *"
az functionapp config appsettings set --name $Fa `
  --resource-group $RgNm `
  --settings "ScheduleCheckResourceSecured=0 */30 5-23 * * *"
az functionapp config appsettings set --name $Fa `
  --resource-group $RgNm `
  --settings "ScheduleDataRecovery=0 0 3 * * *"
az functionapp config appsettings set --name $Fa `
  --resource-group $RgNm `
  --settings "ScheduleExchangeReservationSync=0 0 1 * * *"
az functionapp config appsettings set --name $Fa `
  --resource-group $RgNm `
  --settings "ScheduleNotificationSubscriptionProcessor=0 0 2 * * *"
az functionapp config appsettings set --name $Fa `
  --resource-group $RgNm `
  --settings "SchedulePointsUpdater=0 01 0 * * *"
az functionapp config appsettings set --name $Fa `
  --resource-group $RgNm `
  --settings "SchedulePriceAndRateUpdater=0 01 0 * * *"
az functionapp config appsettings set --name $Fa `
  --resource-group $RgNm `
  --settings "ScheduleResourceConfirmationProcessor=0 */15 * * * *"
az functionapp config appsettings set --name $Fa `
  --resource-group $RgNm `
  --settings "ScheduleResourceReleaseProcessor=0 01 0 * * *"
az functionapp config appsettings set --name $Fa `
  --resource-group $RgNm `
  --slot-settings "SystemUserID=$SystemUserId"
az functionapp config appsettings set --name $Fa `
  --resource-group $RgNm `
  --slot-settings "TrialEndDay=""@Microsoft.AppConfiguration(Endpoint=https://jp-rbs-wak-any-appConfig.azconfig.io; Key=${Id}:TrialEndDay)"""
az functionapp config appsettings set --name $Fa `
  --resource-group $RgNm `
  --slot-settings "TrialStartDay=""@Microsoft.AppConfiguration(Endpoint=https://jp-rbs-wak-any-appConfig.azconfig.io; Key=${Id}:TrialStartDay)"""
az functionapp config appsettings set --name $Fa `
  --resource-group $RgNm `
  --settings "UpdateReservationStatusQueueName=queue-updatereservationgroupstatus-items"
az functionapp config appsettings set --name $Fa `
  --resource-group $RgNm `
  --slot-settings "WEBSITE_AUTH_AAD_ALLOWED_TENANTS=$tenantId,$CustomerTenant"
az functionapp config appsettings set --name $Fa `
  --resource-group $RgNm `
  --settings "WEBSITE_DNS_SERVER=168.63.129.16"
az functionapp config appsettings set --name $Fa `
  --resource-group $RgNm `
  --settings "WEBSITE_TIME_ZONE=Tokyo Standard Time"
az functionapp config appsettings set --name $Fa `
  --resource-group $RgNm `
  --settings "WEBSITE_USE_PLACEHOLDER_DOTNETISOLATED=1"
az webapp auth config-version upgrade --name $Fa --resource-group $RgNm
az extension add --name authV2
az webapp auth update --name $Fa `
  --resource-group $RgNm `
  --redirect-provider "azureactivedirectory" `
  --action RedirectToLoginPage `
  --enabled true `
  --enable-token-store true `
  --set identityProviders.azureActiveDirectory.isAutoProvisioned=$True `
  --excluded-paths "[/$id/api/GetReservationInformationCSV,/$id/api/NotifyClient,/$id/api/LifecycleNotifyClient]"
az webapp auth update --name $Fa `
  --resource-group $RgNm `
  --proxy-convention Custom `
  --proxy-custom-host-header "X-Original-Host"
az webapp auth microsoft update --name $Fa `
  --resource-group $RgNm `
  --client-id $FaAppId `
  --client-secret "$FaAppSecret" `
  --issuer "https://login.microsoftonline.com/common/v2.0" `
  --allowed-audiences "api://$FaAppId, https://ITKDEV2024RSV01.onmicrosoft.com/$FaAppId" `
  --yes
az webapp auth update --name $Fa `
  --resource-group $RgNm `
  --set httpSettings.routes.apiPrefix="/$Id/api/.auth"
az webapp auth update --name $Fa `
  --resource-group $RgNm `
  --set login.routes.logoutEndpoint="/.auth/logout"
$FaARAppId = (az ad app list --display-name $FaAR | ConvertFrom-Json)[0].appId
$FaAuthSettingsId = "/subscriptions/$SubscriptionId/resourceGroups/$RgNm/providers/Microsoft.Web/sites/$Fa/config/authsettingsV2"
az resource update `
  --ids $FaAuthSettingsId `
  --set properties.identityProviders.azureActiveDirectory.registration.clientAppId=$FaARAppId `
        properties.identityProviders.azureActiveDirectory.validation.defaultAuthorizationPolicy.allowedApplications[0]=$FaARAppId `
        properties.identityProviders.azureActiveDirectory.validation.defaultAuthorizationPolicy.allowedApplications[1]=$CustomerAppId
az functionapp cors add --name $Fa `
  --resource-group $RgNm `
  --allowed-origins "https://portal.azure.com" "https://localhost:3000" "http://localhost:3000" "$PublicSAURL"
az functionapp cors credentials --name $Fa `
  --resource-group $RgNm `
  --enable $true
$result = az functionapp deployment slot create --name $Fa `
  --resource-group $RgNm `
  --slot "stg" `
  --configuration-source $Fa
$result = az functionapp config set --resource-group $RgNm `
  --name $Fa `
  --use-32bit-worker-process false `
  --always-on true `
  --ftps-state Disabled `
  --http20-enabled false `
  --min-tls-version "1.2" `
  --slot "stg"
(az webapp config show --resource-group $RgNm --name $Fa | ConvertFrom-Json) | Select-Object name, use32bitworkerprocess, alwaysOn, ftpsState, http20Enabled, minTlsVersion, netFrameworkVersion
(az resource show --resource-group $RgNm --name ftp --namespace Microsoft.Web --resource-type basicPublishingCredentialsPolicies --parent sites/$Fa | ConvertFrom-Json) | Select-Object @{Name='FtpAllow'; Expression={$_.properties.allow}} | Format-Table -AutoSize
(az resource show --resource-group $RgNm --name scm --namespace Microsoft.Web --resource-type basicPublishingCredentialsPolicies --parent sites/$Fa | ConvertFrom-Json) | Select-Object @{Name='ScmAllow'; Expression={$_.properties.allow}} | Format-Table -AutoSize
$result = az functionapp identity show --resource-group $RgNm --name $Fa --slot "stg"
$FaSystemStgId = ($result | ConvertFrom-Json).principalId
az functionapp config appsettings set --name $Fa --slot stg `
  --resource-group $RgNm `
  --settings "AddinAppId=$AddinAppId"
az functionapp config appsettings set --name $Fa --slot stg `
  --resource-group $RgNm `
  --settings "AddinSiteURL=https://$PublicSANm.z11.web.core.windows.net"
az functionapp config appsettings set --name $Fa --slot stg `
  --resource-group $RgNm `
  --settings "AzureFunctionsJobHost__extensions__http__routePrefix=$Id/api/"
az functionapp config appsettings set --name $Fa --slot stg `
  --resource-group $RgNm `
  --settings "AzureFunctionsJobHost__functionTimeout=02:00:00"
az functionapp config appsettings set --name $Fa --slot stg `
  --resource-group $RgNm `
  --slot-settings "AzureWebJobs.CheckConsistency.Disabled=1"
az functionapp config appsettings set --name $Fa --slot stg `
  --resource-group $RgNm `
  --slot-settings "AzureWebJobs.CheckNotificationEntityTimeouts.Disabled=1"
az functionapp config appsettings set --name $Fa --slot stg `
  --resource-group $RgNm `
  --slot-settings "AzureWebJobs.ExchangeReservationSync.Disabled=1"
az functionapp config appsettings set --name $Fa --slot stg `
  --resource-group $RgNm `
  --slot-settings "AzureWebJobs.HandleNotification.Disabled=1"
az functionapp config appsettings set --name $Fa --slot stg `
  --resource-group $RgNm `
  --slot-settings "AzureWebJobs.NotificationSubscriptionProcessor.Disabled=1"
az functionapp config appsettings set --name $Fa --slot stg `
  --resource-group $RgNm `
  --slot-settings "AzureWebJobs.PointsUpdater.Disabled=1"
az functionapp config appsettings set --name $Fa --slot stg `
  --resource-group $RgNm `
  --slot-settings "AzureWebJobs.PriceAndRateUpdater.Disabled=1"
az functionapp config appsettings set --name $Fa --slot stg `
  --resource-group $RgNm `
  --slot-settings "AzureWebJobs.RADataRecovery.Disabled=1"
az functionapp config appsettings set --name $Fa --slot stg `
  --resource-group $RgNm `
  --slot-settings "AzureWebJobs.ReservationStatusUpdater.Disabled=1"
az functionapp config appsettings set --name $Fa --slot stg `
  --resource-group $RgNm `
  --slot-settings "AzureWebJobs.ResourceConfirmationProcessor.Disabled=1"
az functionapp config appsettings set --name $Fa --slot stg `
  --resource-group $RgNm `
  --slot-settings "AzureWebJobs.ResourceReleaseProcessor.Disabled=1"
az functionapp config appsettings set --name $Fa --slot stg `
  --resource-group $RgNm `
  --settings "BlobLocksContainerName=reservation-bloblocks"
az functionapp config appsettings set --name $Fa --slot stg `
  --resource-group $RgNm `
  --settings "CheckConsistencyQueueName=queue-checkconsistencyqueue-items"
az functionapp config appsettings set --name $Fa --slot stg `
  --resource-group $RgNm `
  --settings "CsvEncryptionSecret=$CsvSecret"
az functionapp config appsettings set --name $Fa --slot stg `
  --resource-group $RgNm `
  --slot-settings "DurableTaskHubName=RANotificationTaskHub"
az functionapp config appsettings set --name $Fa --slot stg `
  --resource-group $RgNm `
  --slot-settings "FunctionSiteURL=$RaURL/$id/api"
az functionapp config appsettings set --name $Fa --slot stg `
  --resource-group $RgNm `
  --settings "GraphConnectionInfo:ClientID=$CustomerAppId"
az functionapp config appsettings set --name $Fa --slot stg `
  --resource-group $RgNm `
  --settings "GraphConnectionInfo:ClientSecret=""@Microsoft.KeyVault(SecretUri=https://$KeyVaultNm.vault.azure.net/secrets/jp-rbs-wak-any-${Id}-GraphAPI)"""
az functionapp config appsettings set --name $Fa --slot stg `
  --resource-group $RgNm `
  --settings "GraphConnectionInfo:TenantID=$CustomerTenant"
az functionapp config appsettings set --name $Fa --slot stg `
  --resource-group $RgNm `
  --settings "HandleNotificationQueueName=queue-handlenotification-items"
az functionapp config appsettings set --name $Fa --slot stg `
  --resource-group $RgNm `
  --slot-settings "HotellingLabelAllowIP=*"
az functionapp config appsettings set --name $Fa --slot stg `
  --resource-group $RgNm `
  --slot-settings "OmakaseResourceMail=$omakase"
az functionapp config appsettings set --name $Fa --slot stg `
  --resource-group $RgNm `
  --slot-settings "RegisterSubscriptionRunMode=ValidateAndRegister"
az functionapp config appsettings set --name $Fa --slot stg `
  --resource-group $RgNm `
  --settings "ScheduleCheckNotificationEntityTimeouts=0 0 * * * *"
az functionapp config appsettings set --name $Fa --slot stg `
  --resource-group $RgNm `
  --settings "ScheduleCheckResourceSecured=0 */30 5-23 * * *"
az functionapp config appsettings set --name $Fa --slot stg `
  --resource-group $RgNm `
  --settings "ScheduleDataRecovery=0 0 3 * * *"
az functionapp config appsettings set --name $Fa --slot stg `
  --resource-group $RgNm `
  --settings "ScheduleExchangeReservationSync=0 0 1 * * *"
az functionapp config appsettings set --name $Fa --slot stg `
  --resource-group $RgNm `
  --settings "ScheduleNotificationSubscriptionProcessor=0 0 2 * * *"
az functionapp config appsettings set --name $Fa --slot stg `
  --resource-group $RgNm `
  --settings "SchedulePointsUpdater=0 01 0 * * *"
az functionapp config appsettings set --name $Fa --slot stg `
  --resource-group $RgNm `
  --settings "SchedulePriceAndRateUpdater=0 01 0 * * *"
az functionapp config appsettings set --name $Fa --slot stg `
  --resource-group $RgNm `
  --settings "ScheduleResourceConfirmationProcessor=0 */15 * * * *"
az functionapp config appsettings set --name $Fa --slot stg `
  --resource-group $RgNm `
  --settings "ScheduleResourceReleaseProcessor=0 01 0 * * *"
az functionapp config appsettings set --name $Fa --slot stg `
  --resource-group $RgNm `
  --slot-settings "SystemUserID=$SystemUserId"
az functionapp config appsettings set --name $Fa --slot stg `
  --resource-group $RgNm `
  --settings "UpdateReservationStatusQueueName=queue-updatereservationgroupstatus-items"
az functionapp config appsettings set --name $Fa --slot stg `
  --resource-group $RgNm `
  --settings "WEBSITE_DNS_SERVER=168.63.129.16"
az functionapp config appsettings set --name $Fa --slot stg `
  --resource-group $RgNm `
  --settings "WEBSITE_TIME_ZONE=Tokyo Standard Time"
az functionapp config appsettings set --name $Fa --slot stg `
  --resource-group $RgNm `
  --settings "WEBSITE_USE_PLACEHOLDER_DOTNETISOLATED=1"
$KeyVaultCommonScope = (az keyvault show -g $RgCommonNm --name $KeyVaultCommonNm | ConvertFrom-Json).id
$result=az role assignment create `
  --role 4633458b-17de-408a-b874-0445c86b69e6 `
  --assignee-object-id $FaSystemStgId `
  --assignee-principal-type ServicePrincipal `
  --scope $KeyVaultCommonScope
($result | ConvertFrom-Json).createdOn
$result=az role assignment create `
  --role 4633458b-17de-408a-b874-0445c86b69e6 `
  --assignee-object-id $FaSystemStgId `
  --assignee-principal-type ServicePrincipal `
  --scope $KeyVaultScope
($result | ConvertFrom-Json).createdOn
az functionapp config appsettings set --name $Fa --slot "stg" `
  --resource-group $RgNm `
  --settings APPLICATIONINSIGHTS_CONNECTION_STRING=$appiconString ApplicationInsightsAgent_EXTENSION_VERSION=~2 XDT_MicrosoftApplicationInsights_Mode=default
az functionapp config appsettings list --name $Fa --slot stg --resource-group $RgNm | ConvertFrom-Json
az webapp config connection-string set --resource-group $RgNm `
  --name $Fa --slot stg `
  --connection-string-type "SQLServer" `
  --settings "ReserveAnyManagementContext=""@Microsoft.KeyVault(SecretUri=$SQLConValue)""" `
  --slot-settings "ReserveAnyManagementContext=""@Microsoft.KeyVault(SecretUri=$SQLConValue)"""
(az storage queue list --account-name $FunctionSANm | ConvertFrom-Json)
az storage blob service-properties update `
  --account-name $PublicSANm `
  --static-website `
  --404-document taskpane.html `
  --index-document taskpane.html
$result = az sql server ad-admin create --display-name "システム管理者" `
  --object-id "7bbd2f4a-d20e-489e-9bef-777f7d850378" `
  --resource-group $RgNm `
  --server $SQLSrv
($result | convertfrom-json)
$result = az sql server ad-only-auth enable `
  --resource-group $RgNm `
  --name $SQLSrv
($result | convertfrom-json).azureAdOnlyAuthentication
$Sqlid=$(az sql server list `
  --resource-group $RgNm `
  --query '[].[id]' `
  --output tsv)
$result = az network private-endpoint create `
    --name "$SQLSrv-pep" `
    --resource-group $RgCommonNm `
    --vnet-name $VNetNm --subnet $SubnetNm `
    --private-connection-resource-id $Sqlid `
    --group-ids sqlServer `
    --connection-name "$SQLSrv-pep-$SubscriptionId"
($result | convertfrom-json).customDnsConfigs
$SQLPrivateIp = ($result | convertfrom-json).customDnsConfigs.ipAddresses
az network private-dns record-set a add-record `
 -g $RgCommonNm `
 -z privatelink.database.windows.net `
 -n "$SQLSrv" `
 -a $SQLPrivateIp
az network private-dns record-set a update `
 -g $RgCommonNm `
 -z privatelink.database.windows.net `
 -n "$SQLSrv" `
 --set ttl=10
$Waid=$(az webapp list `
    --resource-group $RgNm `
    --query '[].[id]' `
    --output tsv)
$result=az network private-endpoint create `
    --name "$Wa-pep" `
    --resource-group $RgCommonNm `
    --vnet-name $VNetNm --subnet $SubnetNm `
    --private-connection-resource-id $Waid `
    --group-ids sites `
    --connection-name "$Wa-pep-$SubscriptionId"
($result | convertfrom-json).customDnsConfigs
$WaPrivateIp = ($result | convertfrom-json).customDnsConfigs[0].ipAddresses
az network private-dns record-set a add-record `
  -g $RgCommonNm `
  -z privatelink.azurewebsites.net `
  -n $Wa `
  -a $WaPrivateIp
az network private-dns record-set a update `
  -g $RgCommonNm `
  -z privatelink.azurewebsites.net `
  -n $Wa `
  --set ttl=10
az network private-dns record-set a add-record `
  -g $RgCommonNm `
  -z privatelink.azurewebsites.net `
  -n "$Wa.scm" `
  -a $WaPrivateIp
az network private-dns record-set a update `
  -g $RgCommonNm `
  -z privatelink.azurewebsites.net `
  -n "$Wa.scm" `
  --set ttl=10
az webapp vnet-integration list --name "$Wa" --resource-group "$RgNm"
$Waid=$(az webapp list `
    --resource-group $RgNm `
    --query '[].[id]' `
    --output tsv)
$result=az network private-endpoint create `
    --name "$Wa-stg-pep" `
    --resource-group $RgCommonNm `
    --vnet-name $VNetNm --subnet $SubnetNm `
    --private-connection-resource-id $Waid `
    --group-ids sites-stg `
    --connection-name "$Wa-stg-pep-$SubscriptionId"
($result | convertfrom-json).customDnsConfigs
$WaStgPrivateIp = ($result | convertfrom-json).customDnsConfigs[0].ipAddresses
az network private-dns record-set a add-record `
  -g $RgCommonNm `
  -z privatelink.azurewebsites.net `
  -n "$Wa-stg" `
  -a $WaStgPrivateIp
az network private-dns record-set a update `
  -g $RgCommonNm `
  -z privatelink.azurewebsites.net `
  -n "$Wa-stg" `
  --set ttl=10
az network private-dns record-set a add-record `
  -g $RgCommonNm `
  -z privatelink.azurewebsites.net `
  -n "$Wa-stg.scm" `
  -a $WaStgPrivateIp
az network private-dns record-set a update `
  -g $RgCommonNm `
  -z privatelink.azurewebsites.net `
  -n "$Wa-stg.scm" `
  --set ttl=10
az webapp vnet-integration list --name "$Wa" --resource-group "$RgNm" --slot "stg"
$Faid=$(az functionapp list `
    --resource-group $RgNm `
    --query '[].[id]' `
    --output tsv)
$result=az network private-endpoint create `
    --name "$Fa-pep" `
    --resource-group $RgCommonNm `
    --vnet-name $VNetNm --subnet $SubnetNm `
    --private-connection-resource-id $Faid `
    --group-ids sites `
    --connection-name "$Fa-pep-$SubscriptionId"
($result | convertfrom-json).customDnsConfigs
$FaPrivateIp = ($result | convertfrom-json).customDnsConfigs[0].ipAddresses
az network private-dns record-set a add-record `
  -g $RgCommonNm `
  -z privatelink.azurewebsites.net `
  -n $Fa `
  -a $FaPrivateIp
az network private-dns record-set a update `
  -g $RgCommonNm `
  -z privatelink.azurewebsites.net `
  -n $Fa `
  --set ttl=10
az network private-dns record-set a add-record `
  -g $RgCommonNm `
  -z privatelink.azurewebsites.net `
  -n "$Fa.scm" `
  -a $FaPrivateIp
az network private-dns record-set a update `
  -g $RgCommonNm `
  -z privatelink.azurewebsites.net `
  -n "$Fa.scm" `
  --set ttl=10
az functionapp vnet-integration list --name "$Fa" --resource-group "$RgNm"
$Faid=$(az functionapp list `
    --resource-group $RgNm `
    --query '[].[id]' `
    --output tsv)
$result=az network private-endpoint create `
    --name "$Fa-stg-pep" `
    --resource-group $RgCommonNm `
    --vnet-name $VNetNm --subnet $SubnetNm `
    --private-connection-resource-id $Faid `
    --group-ids "sites-stg" `
    --connection-name "$Fa-stg-pep-$SubscriptionId"
($result | convertfrom-json).customDnsConfigs
$FaStgPrivateIp = ($result | convertfrom-json).customDnsConfigs[0].ipAddresses
az network private-dns record-set a add-record `
  -g $RgCommonNm `
  -z privatelink.azurewebsites.net `
  -n "$Fa-stg" `
  -a $FaStgPrivateIp
az network private-dns record-set a update `
  -g $RgCommonNm `
  -z privatelink.azurewebsites.net `
  -n "$Fa-stg" `
  --set ttl=10
az network private-dns record-set a add-record `
  -g $RgCommonNm `
  -z privatelink.azurewebsites.net `
  -n "$Fa-stg.scm" `
  -a $FaStgPrivateIp
az network private-dns record-set a update `
  -g $RgCommonNm `
  -z privatelink.azurewebsites.net `
  -n "$Fa-stg.scm" `
  --set ttl=10
az functionapp vnet-integration list --name "$Fa" --resource-group "$RgNm" --slot "stg"
$FunctionSAId = az storage account show --name $FunctionSANm --resource-group $RgNm --query id --output tsv
$result = az network private-endpoint create `
    --name "${FunctionSANm}-blob-pep" `
    --resource-group $RgCommonNm `
    --vnet-name $VNetNm --subnet $SubnetNm `
    --private-connection-resource-id $FunctionSAid `
    --group-ids "blob" `
    --connection-name "${FunctionSANm}-blob-pep-$SubscriptionId"
($result | convertfrom-json).customDnsConfigs
$BlobPrivateIp = ($result | convertfrom-json).customDnsConfigs[0].ipAddresses
az network private-dns record-set a add-record `
  -g $RgCommonNm `
  -z privatelink.blob.core.windows.net `
  -n $FunctionSANm `
  -a $BlobPrivateIp
az network private-dns record-set a update `
  -g $RgCommonNm `
  -z privatelink.blob.core.windows.net `
  -n $FunctionSANm `
  --set ttl=10
$result = az network private-endpoint create `
    --name "${FunctionSANm}-queue-pep" `
    --resource-group $RgCommonNm `
    --vnet-name $VNetNm --subnet $SubnetNm `
    --private-connection-resource-id $FunctionSAid `
    --group-ids "queue" `
    --connection-name "${FunctionSANm}-queue-pep-$SubscriptionId"
($result | convertfrom-json).customDnsConfigs
$QueuePrivateIp = ($result | convertfrom-json).customDnsConfigs[0].ipAddresses
az network private-dns record-set a add-record `
  -g $RgCommonNm `
  -z privatelink.queue.core.windows.net `
  -n $FunctionSANm `
  -a $QueuePrivateIp
az network private-dns record-set a update `
  -g $RgCommonNm `
  -z privatelink.queue.core.windows.net `
  -n $FunctionSANm `
  --set ttl=10
$result = az network private-endpoint create `
    --name "${FunctionSANm}-table-pep" `
    --resource-group $RgCommonNm `
    --vnet-name $VNetNm --subnet $SubnetNm `
    --private-connection-resource-id $FunctionSAid `
    --group-ids "table" `
    --connection-name "${FunctionSANm}-table-pep-$SubscriptionId"
($result | convertfrom-json).customDnsConfigs
$TablePrivateIp = ($result | convertfrom-json).customDnsConfigs[0].ipAddresses
az network private-dns record-set a add-record `
  -g $RgCommonNm `
  -z privatelink.table.core.windows.net `
  -n $FunctionSANm `
  -a $TablePrivateIp
az network private-dns record-set a update `
  -g $RgCommonNm `
  -z privatelink.table.core.windows.net `
  -n $FunctionSANm `
  --set ttl=10
az appconfig kv set --name $appConfigName `
  --key "$Id`:AllFeatureFlg" `
  --value "TRUE" `
  --yes
az appconfig kv set --name $appConfigName `
  --key "$Id`:ConditionsReservationFeatureFlg" `
  --value "TRUE" `
  --yes
az appconfig kv set --name $appConfigName `
  --key "$Id`:DPFeatureFlg" `
  --value "TRUE" `
  --yes
az appconfig kv set --name $appConfigName `
  --key "$Id`:HotellingCSVFeatureFlg" `
  --value "TRUE" `
  --yes
az appconfig kv set --name $appConfigName `
  --key "$Id`:HotellingFeatureFlg" `
  --value "TRUE" `
  --yes
az appconfig kv set --name $appConfigName `
  --key "$Id`:TrialEndDay" `
  --value "9999/12/31" `
  --yes
az appconfig kv set --name $appConfigName `
  --key "$Id`:TrialStartDay" `
  --value "1900/1/1" `
  --yes
$AppConfigCommonScope = (az appconfig show -g $RgCommonNm --name $appConfigName | ConvertFrom-Json).id
$WaSystemId = (az webapp identity show `
  --resource-group $RgNm `
  --name $Wa | ConvertFrom-Json).principalId
$result=az role assignment create `
  --role 5ae67dd6-50cb-40e7-96ff-dc2bfa4b606b `
  --assignee-object-id $WaSystemId --assignee-principal-type ServicePrincipal `
  --scope $AppConfigCommonScope
($result | ConvertFrom-Json).createdOn
$FaSystemId = (az functionapp identity show `
  --resource-group $RgNm `
  --name $Fa | ConvertFrom-Json).principalId
$result=az role assignment create `
  --role 5ae67dd6-50cb-40e7-96ff-dc2bfa4b606b `
  --assignee-object-id $FaSystemId --assignee-principal-type ServicePrincipal `
  --scope $AppConfigCommonScope
($result | ConvertFrom-Json).createdOn
az monitor diagnostic-settings create `
  --name $WaDiag `
  --resource $(az webapp show --name $Wa --resource-group $RgNm --query id -o tsv) `
  --workspace $workspaceid `
  --logs '[{"category":"AppServiceHTTPLogs","enabled":true},{"category":"AppServiceConsoleLogs","enabled":true},{"category":"AppServiceAppLogs","enabled":true},{"category":"AppServiceAuditLogs","enabled":true},{"category":"AppServiceIPSecAuditLogs","enabled":true},{"category":"AppServicePlatformLogs","enabled":true},{"category":"AppServiceAuthenticationLogs","enabled":true},{"category":"AppServiceAntivirusScanAuditLogs","enabled":true},{"category":"AppServiceFileAuditLogs","enabled":true}]' `
  --metrics '[{"category":"AllMetrics","enabled":true}]'
az monitor diagnostic-settings create `
  --name $FaDiag `
  --resource $(az webapp show --name $Fa --resource-group $RgNm --query id -o tsv) `
  --workspace $workspaceid `
  --logs '[{"category":"FunctionAppLogs","enabled":true},{"category":"AppServiceAuthenticationLogs","enabled":true}]' `
  --metrics '[{"category":"AllMetrics","enabled":true}]'
az monitor diagnostic-settings create `
  --name $AppPlanDiag `
  --resource $(az appservice plan show --name $AppPlan --resource-group $RgNm --query id -o tsv) `
  --workspace $workspaceid `
  --metrics '[{"category":"AllMetrics","enabled":true}]'
az monitor diagnostic-settings create `
  --name $KeyVaultNmDiag `
  --resource $(az keyvault show --name $KeyVaultNm --resource-group $RgNm --query id -o tsv) `
  --workspace $workspaceid `
  --logs '[{"categoryGroup":"audit","enabled":true},{"categoryGroup":"allLogs","enabled":true}]' `
  --metrics '[{"category":"AllMetrics","enabled":true}]'
az monitor diagnostic-settings create `
  --name $SQLDbDiag `
  --resource $(az sql db show -g $RgNm -n $SQLDb --server $SQLSrv --query id -o tsv) `
  --workspace $workspaceid `
  --logs '[{"categoryGroup":"allLogs","enabled":true},{"categoryGroup":"audit","enabled":true}]' `
  --metrics '[{"category":"Basic","enabled":true},{"category":"InstanceAndAppAdvanced","enabled":true},{"category":"WorkloadManagement","enabled":true}]'
az monitor diagnostic-settings create `
  --name $FunctionSADiag `
  --resource $(az storage account show -g $RgNm -n $FunctionSANm --query id -o tsv) `
  --workspace $workspaceid `
  --metrics '[{"category":"Transaction","enabled":true}]'
az monitor diagnostic-settings create `
  --name $FunctionSAblobDiag `
  --resource "$(az storage account show -g $RgNm -n $FunctionSANm --query "id" -o tsv)/blobServices/default" `
  --workspace $workspaceid `
  --logs '[{"categoryGroup":"allLogs","enabled":true}]' `
  --metrics '[{"category":"Transaction","enabled":true}]'
az monitor diagnostic-settings create `
  --name $FunctionSAqueueDiag `
  --resource "$(az storage account show -g $RgNm -n $FunctionSANm --query "id" -o tsv)/queueServices/default" `
  --workspace $workspaceid `
  --logs '[{"categoryGroup":"allLogs","enabled":true}]' `
  --metrics '[{"category":"Transaction","enabled":true}]'
az monitor diagnostic-settings create `
  --name $FunctionSAtableDiag `
  --resource "$(az storage account show -g $RgNm -n $FunctionSANm --query "id" -o tsv)/tableServices/default" `
  --workspace $workspaceid `
  --logs '[{"categoryGroup":"allLogs","enabled":true}]' `
  --metrics '[{"category":"Transaction","enabled":true}]'
az monitor diagnostic-settings create `
  --name $FunctionSAfileDiag `
  --resource "$(az storage account show -g $RgNm -n $FunctionSANm --query "id" -o tsv)/fileServices/default" `
  --workspace $workspaceid `
  --logs '[{"categoryGroup":"allLogs","enabled":true}]' `
  --metrics '[{"category":"Transaction","enabled":true}]'
  
