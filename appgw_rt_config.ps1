$location = "japan east"
$SubscriptionId = (az account show | convertfrom-json).id
$tenantId = (az account show | convertfrom-json).tenantId
$Id = "010"
$agwId = "02"
$ResourceDefaultNm = "jp.rbs.wak-any"
$ResourceDefaultNmhyphen = "jp-rbs-wak-any"
$ResourceBaseNm = "$ResourceDefaultNm-$Id"
$ResourceBaseNmhyphen = "$ResourceDefaultNmhyphen-$Id"
$RgNm = "$ResourceBaseNm-rg"
$RgCommonNm = "$ResourceDefaultNm-rg"
$VNetNm = "$ResourceDefaultNm-vnet-spoke"
$OperationUser = (az account show | convertfrom-json).user.name
$KeyVaultCommonNm = "$ResourceDefaultNmhyphen-kv2"
$agwNm = "$ResourceDefaultNm-agw$agwId"
$agwWafpolicy = "$ResourceDefaultNm-wafpolicy02"
$agwbackendpooldefault = "$ResourceDefaultNm-default-backend"
$agwbackendpoolwa = "$ResourceDefaultNm-$Id-wa-backend"
$agwbackendpoolfa = "$ResourceDefaultNm-$Id-fa-backend"
$agwbackendsettingdefault = "$ResourceDefaultNm-default-backendSetting"
$agwbackendsettingwa = "$ResourceDefaultNm-$Id-wa-backendSetting"
$agwbackendsettingfa = "$ResourceDefaultNm-$Id-fa-backendSetting"
$agwbackenddefaulttarget = "$ResourceDefaultNm-default-target"
$agwbackendtargetwa = "$ResourceDefaultNm-$Id-wa-backendtarget"
$agwbackendtargetfa = "$ResourceDefaultNm-$Id-fa-backendtarget"
$agwAffinitywa = "AGA${Id}wa"
$agwAffinityfa = "AGA${Id}fa"
$agwhealthprobewa = "$ResourceDefaultNm-$Id-wa-health"
$agwhealthprobefa = "$ResourceDefaultNm-$Id-fa-health"
$agwListner = "$ResourceDefaultNm-Listner"
$agwRouteRule = "$ResourceDefaultNm-RouteRule$agwId"
$agwWildCard = "*.rbsdevtest2.com"
$agwFuncAppRewrite = "FuncAppCommonRules"
$agwWebAppRewrite = "WebAppCommonRules"
$agwDefaultNm = "snet-agw-biz"
$agwSubnetNm = "$agwDefaultNm-$agwId"
$agwSubnetNmCIDR = "172.16.16.0/24"
$agw = "$ResourceDefaultNm-agw$agwId"
$agwpip = "$ResourceDefaultNm-agw$agwId-pip"
$agwIPConfig = "appGatewayIpConfig-$agwId"
$agwFIPConfig = "appGwPublicFrontendIpIPv4-$agwId"
$agwcertname = (az keyvault certificate list --vault-name $KeyVaultCommonNm |ConvertFrom-Json).name
$Wa = "$ResourceDefaultNmhyphen-$Id-wa02"
$Fa = "$ResourceDefaultNmhyphen-$Id-fa02"
$WaDiag = "$Wa-diag"
$FaDiag = "$Fa-diag"
$AppPlan = "$ResourceDefaultNmhyphen-$Id-asp02"
$KeyVaultNm = "jprbswakany${Id}-kv02"
$SQLSrv = "$ResourceBaseNmhyphen-sql02"
$SQLDb = "$ResourceBaseNmhyphen-sqldb02"
$FunctionSANm = "jprbswakany${Id}fs02"
$AppPlanDiag = "$AppPlan-diag"
$KeyVaultNmDiag = "$KeyVaultNm-diag"
$SQLDbDiag = "$SQLDb-diag"
$FunctionSADiag = "$FunctionSANm-diag"
$FunctionSAblobDiag = "$FunctionSANm-blob-diag"
$FunctionSAqueueDiag = "$FunctionSANm-queue-diag"
$FunctionSAtableDiag = "$FunctionSANm-table-diag"
$FunctionSAfileDiag = "$FunctionSANm-file-diag"
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
$LogAnalyticsNm = "$ResourceBaseNmhyphen-log"
$workspaceid = (az monitor log-analytics workspace show --resource-group $RgNm --name $LogAnalyticsNm | ConvertFrom-Json).id
Write-Host "Resource Default Name: $ResourceDefaultNm"
Write-Host "Resource Group: $RgCommonNm"

$backendPoolwa =  (az network application-gateway address-pool create `
--resource-group $RgCommonNm `
--gateway-name $agwNm `
--name $agwbackendpoolwa `
--servers "$Wa.azurewebsites.net" `
| ConvertFrom-Json)
$probewa = (az network application-gateway probe create `
-g $RgCommonNm `
--gateway-name $agwNm `
-n $agwhealthprobewa `
--protocol https `
--host "$Wa.azurewebsites.net" `
--path "/${Id}/admin/.auth/login/aad/callback" `
--interval 30 `
--timeout 30 `
--threshold 3 `
--min-servers 0 `
| ConvertFrom-Json).Id
$httpSettingwa = (az network application-gateway http-settings create `
-g $RgCommonNm `
--gateway-name $agwNm `
-n $agwbackendsettingwa `
--port 443 `
--protocol Https `
--cookie-based-affinity Enabled `
--affinity-cookie-name "AGA${Id}wa" `
--timeout 20 `
--host-name-from-backend-pool 1 `
--probe $probewa `
| ConvertFrom-Json).Id
$UrlPathMapId = az network application-gateway rule show `
--gateway-name $agwNm `
--resource-group $RgCommonNm `
--name $agwRouteRule `
--query "urlPathMap.id"
$PathRuleWa = (az network application-gateway url-path-map rule create `
--gateway-name $agwNm `
--resource-group $RgCommonNm `
--path-map-name $agwRouteRule `
--name $agwbackendtargetwa `
--paths "/${Id}/admin/*" `
--address-pool $agwbackendpoolwa `
--http-settings $httpSettingwa `
| ConvertFrom-Json)
$backendPoolfa =  (az network application-gateway address-pool create `
--resource-group $RgCommonNm `
--gateway-name $agwNm `
--name $agwbackendpoolfa `
--servers "$Fa.azurewebsites.net" `
| ConvertFrom-Json)
$probefa = (az network application-gateway probe create `
-g $RgCommonNm `
--gateway-name $agwNm `
-n $agwhealthprobefa `
--protocol https `
--host "$Fa.azurewebsites.net" `
--path "/${Id}/api/.auth/login/aad/callback" `
--interval 30 `
--timeout 30 `
--threshold 3 `
--min-servers 0 `
| ConvertFrom-Json).Id
$httpSettingfa = (az network application-gateway http-settings create `
-g $RgCommonNm `
--gateway-name $agwNm `
-n $agwbackendsettingfa `
--port 443 `
--protocol Https `
--cookie-based-affinity Enabled `
--affinity-cookie-name "AGA${Id}fa" `
--timeout 220 `
--host-name-from-backend-pool 1 `
--probe $probefa `
| ConvertFrom-Json).Id
$UrlPathMapId = az network application-gateway rule show `
--gateway-name $agwNm `
--resource-group $RgCommonNm `
--name $agwRouteRule `
--query "urlPathMap.id"
$PathRuleFa = (az network application-gateway url-path-map rule create `
--gateway-name $agwNm `
--resource-group $RgCommonNm `
--path-map-name $agwRouteRule `
--name $agwbackendtargetfa `
--paths "/${Id}/api/*" `
--address-pool $agwbackendpoolfa `
--http-settings $httpSettingfa `
| ConvertFrom-Json)
$appGw = Get-AzApplicationGateway -Name $agwNm -ResourceGroupName $RgCommonNm
$AzUrlPathMap = $appGw.UrlPathMaps | Where-Object { $_.Name -eq $agwRouteRule }
$AzPathRuleWa = $AzUrlPathMap.PathRules | Where-Object { $_.Name -eq $agwbackendtargetwa }
$rewriteRuleSetNameWa = "WebAppCommonRules"
$rewriteRuleSet = $appGw.RewriteRuleSets | Where-Object { $_.Name -eq $rewriteRuleSetNameWa }
$AzPathRuleWa.RewriteRuleSet = $rewriteRuleSet
Set-AzApplicationGateway -ApplicationGateway $appGw
$AzPathRuleFa = $AzUrlPathMap.PathRules | Where-Object { $_.Name -eq $agwbackendtargetfa }
$rewriteRuleSetNameFa = "FuncAppCommonRules"
$rewriteRuleSet = $appGw.RewriteRuleSets | Where-Object { $_.Name -eq $rewriteRuleSetNameFa }
$AzPathRuleFa.RewriteRuleSet = $rewriteRuleSet
Set-AzApplicationGateway -ApplicationGateway $appGw
$WaPep = az network private-endpoint show `
--name "$Wa-pep" `
--resource-group $RgCommonNm | ConvertFrom-Json
$WaPrivateIp = $WaPep.customDnsConfigs[0].ipAddresses[0]
az network route-table route create `
--address-prefix $WaPrivateIp/32 `
--name "$ResourceDefaultNm-rt-to-$Id-wa02" `
--next-hop-ip-address 192.168.100.4 `
--next-hop-type VirtualAppliance `
--resource-group $RgCommonNm `
--route-table-name $RtSpoke2hub
$FaPep = az network private-endpoint show `
    --name "$Fa-pep" `
    --resource-group $RgCommonNm | ConvertFrom-Json
$FaPrivateIp = $FaPep.customDnsConfigs[0].ipAddresses[0]
az network route-table route create `
--address-prefix $FaPrivateIp/32 `
--name "$ResourceDefaultNm-rt-to-$Id-fa02" `
--next-hop-ip-address 192.168.100.4 `
--next-hop-type VirtualAppliance `
--resource-group $RgCommonNm `
--route-table-name $RtSpoke2hub
