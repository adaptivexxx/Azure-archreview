//Storage Account Misconfiguration Detection Using Azure Resource Graph Explorer

resources
| where type == "microsoft.storage/storageaccounts"
| extend
    properties.networkAcls,
    properties.allowSharedKeyAccess,
    properties.supportsHttpsTrafficOnly,
    properties.minimumTlsVersion,
    properties.allowBlobPublicAccess,
    properties.isHnsEnabled
| project
    name,
    resourceGroup,
    subscriptionId,
    kind,
    sku = sku.name,
    
    // Network Security
    publicNetworkAccess = iff(networkAcls.defaultAction == "Allow", "Public", "Restricted"),
    ipRestrictions = iff(isnotempty(networkAcls.ipRules), "Enabled", "None"),
    vnetRestrictions = iff(isnotempty(networkAcls.virtualNetworkRules), "Enabled", "None"),
    bypass = networkAcls.bypass,
    
    // Authentication
    sharedKeyAccess = iff(isnull(allowSharedKeyAccess), "Unknown", iff(allowSharedKeyAccess, "Enabled", "Disabled")),
    
    // Encryption & TLS
    httpsOnly = iff(supportsHttpsTrafficOnly, "Enabled", "Disabled"),
    tlsVersion = minimumTlsVersion,
    
    // Data Protection
    blobPublicAccess = iff(isnull(allowBlobPublicAccess), "Unknown", iff(allowBlobPublicAccess, "Enabled", "Disabled")),
    hierarchicalNamespace = iff(isHnsEnabled, "Enabled", "Disabled")
    
| where 
    publicNetworkAccess == "Public" or
    sharedKeyAccess == "Enabled" or
    httpsOnly == "Disabled" or
    tolower(tlsVersion) != "tls1_2" or
    blobPublicAccess == "Enabled"
| order by publicNetworkAccess desc, name asc
