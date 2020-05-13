<#
.SYNOPSIS
    Check Azure Policy for non-compliant virtual networks and apply the DDoS Standard Protection Plan.
    This runbook should be scheduled to run once a day as Azure Policy evaluation cycle runs once a day.

.DESCRIPTION
    This runbook connects to Azure and performs the following tasks:
        - Query Azure Policy for non-compliant resources based on the policy definition name
        - Store details of the non-compliant resources (vnets)
        - Apply DDoS settings to each non-compliant vnets

.PARAMETER managementGroupName
    Optional with no default.
    The management group name the Azure Policy is scoped to.
    If subscriptionID is specified, leave this parameter null (blank/empty)
    Either subscriptionID or managementgroupName must be specified.

.PARAMETER subscriptionID
    Optional with no default.
    The ID of an Azure Subscription that the Azure Policy is scoped to.
    If managementGroupName is specified, leave this parameter null (blank/empty).
    Either subscriptionID or managementgroupName must be specified.

.PARAMETER resourceGroupName
    Optional with no default.
    The resource group name the Azure Policy assignment is scoped to.
    subscriptionID needs to be specified as well for this to work.
    Both subscriptionID or ResourceGroupName must be specified.
    managementGroupName must not be specified if resourceGroupName is specified.

.PARAMETER policyDefName
    Optional with no default.
    The policy definition name.
    For built in policy, it is in GUID format.

.PARAMETER policyAssignmentName
    Optional with no default.
    The policy assignment name in GUID format.


.NOTES
	Created By: Eric Yew - OLIKKA
	LAST EDIT: Jan 30, 2020
	    By: Eric Yew
	SOURCE: https://github.com/Olikka/Azure-Policy/
#>

param(
    [Parameter(Mandatory=$false)] 
    [String] $managementGroupName,

    [Parameter(Mandatory=$false)] 
    [String] $subscriptionID,
    
    [parameter(Mandatory=$false)] 
    [String] $resourceGroupName,

    [parameter(Mandatory=$true)] 
    [String] $policyDefName,

    [parameter(Mandatory=$false)] 
    [String] $policyAssignmentName
)

$connectionName = "AzureRunAsConnection"
try
{
    # Get the connection "AzureRunAsConnection "
    $servicePrincipalConnection=Get-AutomationConnection -Name $connectionName         

    "Logging in to Azure..."
    Connect-AzAccount `
        -ServicePrincipal `
        -Tenant $servicePrincipalConnection.TenantId `
        -ApplicationId $servicePrincipalConnection.ApplicationId `
        -CertificateThumbprint $servicePrincipalConnection.CertificateThumbprint 
}
catch {
    if (!$servicePrincipalConnection)
    {
        $ErrorMessage = "Connection $connectionName not found."
        throw $ErrorMessage
    } else{
        Write-Error -Message $_.Exception
        throw $_.Exception
    }
}


#Gets the policy definition based on the scope supplied
    if(!$managementGroupName -And $subscriptionID){
        Set-AzContext -SubscriptionId $subscriptionID
        $polDef = Get-AzPolicyDefinition -Name $PolicyDefName -SubscriptionId $subscriptionID    
    }elseif($managementGroupName -And !$subscriptionID){
        $polDef = Get-AzPolicyDefinition -Name $PolicyDefName -ManagementGroupName $managementGroupName
    }else{
        throw 'No management group or subscription specified'
    }

#Get policy assignment details
    if(!$policyAssignmentName){
        $polAssignments = Get-AzPolicyAssignment -PolicyDefinitionId $polDef.PolicyDefinitionId

        foreach ($polAssignment in $polAssignments) {
            $policyAssignmentName = $polAssignment.Name
            #Get DDoSPlanID on assignment
            $DDoSPlanID = $polAssignment.Properties.parameters.DDoSPlan.value
            # Set-AzContext -Subscription "2cb8e9ca-0cc2-4ca3-9eb2-9080577c6403"
            
            #Gets all non-compliant vnets
                if (!$polAssignment.ResourceGroupName){
                    $resources = Get-AzPolicyState -SubscriptionId $subscriptionID -PolicyAssignmentName $policyAssignmentName
                }else{
                    $resources = Get-AzPolicyState -SubscriptionId $subscriptionID -PolicyAssignmentName $policyAssignmentName -ResourceGroupName $polAssignment.ResourceGroupName
                }

            #Applies DDoS Standard Protection Plan to resources
                foreach ($resource in $resources) {
                    Set-AzContext -Subscription $resource.SubscriptionId
                    $vnetID = $resource.ResourceID -split "/"
                    $vnetName = $vnetID[8]
                    $vnet = Get-AzVirtualNetwork -name $vnetName -ResourceGroupName $resource.ResourceGroup
                    $vnet.DdosProtectionPlan = New-Object Microsoft.Azure.Commands.Network.Models.PSResourceId
                    $vnet.DdosProtectionPlan.Id = $DDoSPlanID
                    $vnet.EnableDdosProtection = $true
                    $vnet | Set-AzVirtualNetwork 
                }
        }
    }else {
        if(!$managementGroupName -And $subscriptionID){
            if($resourceGroupName){
                $polAssignment = Get-AzPolicyAssignment -Name $policyAssignmentName -SubscriptionId $subscriptionID -ResourceGroupName $resourceGroupName
            }else {
                $polAssignment = Get-AzPolicyAssignment -Name $policyAssignmentName -SubscriptionId $subscriptionID
            }        
        }elseif($managementGroupName -And !$subscriptionID){
            $polAssignment = Get-AzPolicyAssignment -Name $policyAssignmentName -ManagementGroupName $managementGroupName
        }
        
        $policyAssignmentName = $polAssignment.Name
        #Get DDoSPlanID on assignment
            $DDoSPlanID = $polAssignment.Properties.parameters.DDoSPlan.value
            
            #Gets all non-compliant vnets
                if (!$polAssignment.ResourceGroupName){
                    $resources = Get-AzPolicyState -SubscriptionId $subscriptionID -PolicyAssignmentName $policyAssignmentName
                }else{
                    $resources = Get-AzPolicyState -SubscriptionId $subscriptionID -PolicyAssignmentName $policyAssignmentName -ResourceGroupName $polAssignment.ResourceGroupName
                }
            
            #Applies DDoS Standard Protection Plan to resources
                foreach ($resource in $resources) {
                    Set-AzContext -Subscription $resource.SubscriptionId
                    $vnetID = $resource.ResourceID -split "/"
                    $vnetName = $vnetID[8]
                    $vnet = Get-AzVirtualNetwork -name $vnetName -ResourceGroupName $resource.ResourceGroup
                    $vnet.DdosProtectionPlan = New-Object Microsoft.Azure.Commands.Network.Models.PSResourceId
                    $vnet.DdosProtectionPlan.Id = $DDoSPlanID
                    $vnet.EnableDdosProtection = $true
                    $vnet | Set-AzVirtualNetwork 
                }
    }    

