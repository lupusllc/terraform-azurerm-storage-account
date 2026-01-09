### Defaults

variable "defaults" {
  default     = {} # Defaults to an empty map.
  description = "Defaults used for resources when nothing is specified for the resource."
  nullable    = false # This will treat null values as unset, which will allow for use of defaults.
  type        = any
}

### Required

variable "required" {
  default     = {} # Defaults to an empty map.
  description = "Required resource values, as applicable."
  nullable    = false # This will treat null values as unset, which will allow for use of defaults.
  type        = any
}

### Dependencies

# This data source from root is used because using data calls in child modules can inadvertently cause resource recreation.
variable "configuration" {
  description = "Configuration data such as Tenant ID and Subscription ID."
  nullable    = false
  type = object({
    client_id       = string
    id              = string
    object_id       = string
    subscription_id = string
    tenant_id       = string
  })
}

### Resources

variable "storage_accounts" {
  default     = [] # Defaults to an empty list.
  description = "Storage Accounts."
  nullable    = false # This will treat null values as unset, which will allow for use of defaults.
  type = list(object({
    ### Basic

    access_tier              = optional(string, null)       # Hot, Cool. Defaults to null for resource default of Hot.
    account_kind             = optional(string, null)       # Storage, StorageV2, BlobStorage, FileStorage, BlockBlobStorage. Defaults to null for resource default of StorageV2, changing may require recreation.
    account_replication_type = optional(string, "ZRS")      # LRS, GRS, RAGRS, ZRS, GZRS, RZRS. Defaults to ZRS, changing may require recreation.
    account_tier             = optional(string, "Standard") # Standard, Premium. Defaults to Standard, changing requires recreation.
    dns_endpoint_type        = optional(string, null)       # Standard, AzureDnsZone. Defaults to null for resource default of Standard, changing requires recreation.
    edge_zone                = optional(string, null)       # If provided, specifies the edge zone. Defaults to null for resource default of null, changing requires recreation.
    large_file_share_enabled = optional(bool, null)         # Enables large file shares. Defaults to null for resource default of false.
    location                 = optional(string, null)
    is_hns_enabled           = optional(bool, null) # Enables Hierarchical Namespace for Data Lake Storage Gen2. Defaults to null for resource default of false, changing requires recreation. 
    name                     = string
    nfsv3_enabled            = optional(bool, null) # Enables NFSv3 protocol support. Defaults to null for resource default of false, changing requires recreation.
    resource_group_name      = optional(string, null)
    static_website = optional(object({
      index_document     = string                 # The name of the index file, example -> index.html.
      error_404_document = optional(string, null) # The name of the 404 error file, example -> 404.html. Defaults to null for resource default of null.
    }), null)                                     # We can't use blank object or it will inject unwanted data, so null is used instead.
    tags = optional(map(string), {})

    ### Access

    allow_nested_items_to_be_public = optional(bool, false) # Allows nested items within containers/blobs to be public. Defaults to false.
    azure_files_authentication = optional(object({
      active_directory = optional(object({ # Required for directory type AD.
        domain_guid         = string
        domain_name         = string
        domain_sid          = optional(string, null)          # Required for directory type AD. Defaults to null for resource default of null.
        forest_name         = optional(string, null)          # Required for directory type AD. Defaults to null for resource default of null.
        netbios_domain_name = optional(string, null)          # Required for directory type AD. Defaults to null for resource default of null.
        storage_sid         = optional(string, null)          # Required for directory type AD. Defaults to null for resource default of null.
      }), null)                                               # We can't use blank object or it will inject unwanted data, so null is used instead.
      default_share_level_permission = optional(string, null) # StorageFileDataSmbShareReader, StorageFileDataSmbShareContributor, StorageFileDataSmbShareElevatedContributor, or None. Defaults to null for resource default of None.
      directory_type                 = string                 # AD, AADDS, AADKERB
    }), null)                                                 # We can't use blank object or it will inject unwanted data, so null is used instead.
    custom_domain = optional(object({
      name          = string                               # The custom domain name.
      use_subdomain = optional(bool, null)                 # Indicates whether indirect CNAME validation is enabled. Defaults to null for resource default of false (unconfirmed).
    }), null)                                              # We can't use blank object or it will inject unwanted data, so null is used instead.
    default_to_oauth_authentication = optional(bool, null) # If true, defaults to OAuth authentication for Blob and Queue services. Defaults to null for resource default of false.
    identity = optional(object({
      type                     = optional(string, "SystemAssigned") # Type of identity. Possible values are: SystemAssigned, UserAssigned, SystemAssigned,UserAssigned, None. Defaults to SystemAssigned.
      user_assigned_identities = optional(list(string), [])         # List of User Assigned Identity resource IDs to associate with the Storage Account. Required if type includes UserAssigned.
    }), null)                                                       # We can't use blank object or it will inject unwanted data, so null is used instead.
    public_network_access_enabled = optional(bool, false)           # Enables public network access. Defaults to false.
    routing = optional(object({
      choice                      = optional(string, null) # MicrosoftRouting, InternetRouting. Defaults to null for resource default of MicrosoftRouting (unconfirmed).
      publish_internet_endpoints  = optional(bool, null)   # Publishes Internet endpoints for routing. Defaults to null for resource default of false.
      publish_microsoft_endpoints = optional(bool, null)   # Publishes Microsoft endpoints for routing. Defaults to null for resource default of false.
    }), null)                                              # We can't use blank object or it will inject unwanted data, so null is used instead.
    sftp_enabled              = optional(bool, false)      # Enables SFTP support. Defaults to false.
    shared_access_key_enabled = optional(bool, null)       # Enables shared access key. Defaults to null for resource default of true.

    ### Network

    network_rules = optional(object({
      bypass         = optional(list(string), ["AzureServices"]) # AzureServices, Logging, Metrics, None. Defaults to AzureServices.
      default_action = optional(string, "Allow")                 # Allow, Deny. Defaults to Allow.
      ip_rules       = optional(list(string), [])                # Defaults to empty list.
      private_link_access = optional(list(object({
        endpoint_resource_id = string
        endpoint_tenant_id   = optional(string, null) # If not provided, will use the tenant ID from the client.
      })), [])                                        # Defaults to empty list.
      virtual_network_subnets = optional(list(object({
        virtual_network_id                  = optional(string, null) # Second priority, if provided will be used with the subnet name.
        virtual_network_name                = optional(string, null) # Ignored if virtual_network_id or virtual_network_subnet_name is provided.
        virtual_network_resource_group_name = optional(string, null) # Ignored if virtual_network_id or virtual_network_subnet_name is provided.
        virtual_network_subnet_id           = optional(string, null) # First priority, if provided will be used.
        virtual_network_subnet_name         = optional(string, null) # Ignored if virtual_network_subnet_id is provided.
      })), [])                                                       # Defaults to empty list.
    }), null)                                                        # We can't use blank object or it will inject unwanted data, so null is used instead.

    ### Properties

    blob_properties = optional(object({
      change_feed_enabled           = optional(bool, null)   # Enables the change feed feature. Defaults to null for resource default of false.
      change_feed_retention_in_days = optional(number, null) # Number of days to retain change feed data. Defaults to null for resource default of null (infinite retention).
      container_delete_retention_policy = optional(object({
        days = optional(number, null) # Number of days to retain deleted containers. Defaults to null for resource default of 7.
      }), null)                       # We can't use blank object or it will inject unwanted data, so null is used instead.
      cors_rule = optional(object({
        allowed_headers    = list(string)              # Headers allowed.
        allowed_methods    = list(string)              # HTTP methods allowed.
        allowed_origins    = list(string)              # Origin domains allowed.
        exposed_headers    = list(string)              # Headers exposed to CORS clients.
        max_age_in_seconds = number                    # Max age in seconds the client should cache the preflight response.
      }), null)                                        # We can't use blank object or it will inject unwanted data, so null is used instead.
      default_service_version = optional(string, null) # The default API version to use if not specified in request. Defaults to null for resource default of null.
      delete_retention_policy = optional(object({
        days                     = optional(number, null) # Number of days to retain deleted blobs. Defaults to null for resource default of 7.
        permanent_delete_enabled = optional(bool, null)   # If true, enables permanent delete for blobs. Defaults to null for resource default of false.
      }), null)                                           # We can't use blank object or it will inject unwanted data, so null is used instead.
      last_access_time_enabled = optional(bool, null)     # Enables tracking of last access time for blobs. Defaults to null for resource default of false.
      restore_policy = optional(object({
        days = optional(number, null)           # Number of days to retain soft deleted blobs for point-in-time restore. Defaults to null for resource default of null (unconfirmed).
      }), null)                                 # We can't use blank object or it will inject unwanted data, so null is used instead.
      versioning_enabled = optional(bool, null) # Enables blob versioning.  Defaults to null for resource default of false.
    }), null)                                   # We can't use blank object or it will inject unwanted data, so null is used instead.

    share_properties = optional(object({
      cors_rule = optional(object({
        allowed_headers    = list(string) # Headers allowed.
        allowed_methods    = list(string) # HTTP methods allowed.
        allowed_origins    = list(string) # Origin domains allowed.
        exposed_headers    = list(string) # Headers exposed to CORS clients.
        max_age_in_seconds = number       # Max age in seconds the client should cache the preflight response.
      }), null)                           # We can't use blank object or it will inject unwanted data, so null is used instead.
      retention_policy = optional(object({
        days = optional(number, null) # Number of days to retain deleted shares. Defaults to null for resource default of 7.
      }), null)                       # We can't use blank object or it will inject unwanted data, so null is used instead.
      smb = optional(object({
        authentication_types            = optional(list(string), []) # NTLM, Kerberos
        channel_encryption_type         = optional(list(string), []) # AES-128-GCM, AES-256-GCM
        kerberos_ticket_encryption_type = optional(list(string), []) # RC4_HMAC, AES256_CTS_HMAC_SHA1_96, AES128_CTS_HMAC_SHA1_96
        multichannel_enabled            = optional(bool, null)       # Multichannel support. Defaults to null for resource default of false.
        versions                        = optional(list(string), []) # SMB2.1, SMB3.0, SMB3.1.1
      }), null)                                                      # We can't use blank object or it will inject unwanted data, so null is used instead.
    }), null)                                                        # We can't use blank object or it will inject unwanted data, so null is used instead.

    queue_properties = optional(object({
      cors_rule = optional(object({
        allowed_headers    = list(string) # Headers allowed.
        allowed_methods    = list(string) # HTTP methods allowed.
        allowed_origins    = list(string) # Origin domains allowed.
        exposed_headers    = list(string) # Headers exposed to CORS clients.
        max_age_in_seconds = number       # Max age in seconds the client should cache the preflight response.
      }), null)                           # We can't use blank object or it will inject unwanted data, so null is used instead.
      hour_metrics = optional(object({
        enabled               = optional(bool, false)  # Indicates whether hour metrics are enabled. Defaults to false.
        include_apis          = optional(bool, null)   # Indicates whether APIs are included in the metrics. Defaults to null for resource default of null (unconfirmed).
        retention_policy_days = optional(number, null) # Number of days to retain metrics. Defaults to null for resource default of null (retention disabled).
        version               = string                 # The version of Storage Analytics to use. Possible values include: "1.0", "2.0", "2.1", "2.2", "2.3", "2015-02-21", "2017-04-17", "2018-03-28".
      }), null)                                        # We can't use blank object or it will inject unwanted data, so null is used instead.
      logging = optional(object({
        delete                = optional(bool, false)  # Indicates whether delete requests are logged. Defaults to false.
        read                  = optional(bool, false)  # Indicates whether read requests are logged. Defaults to false.
        write                 = optional(bool, false)  # Indicates whether write requests are logged. Defaults to false.
        version               = string                 # The version of Storage Analytics to use. Possible values include: "1.0", "2.0", "2.1", "2.2", "2.3", "2015-02-21", "2017-04-17", "2018-03-28".
        retention_policy_days = optional(number, null) # Number of days to retain logs. Defaults to null for resource default of null (retention disabled).
      }), null)                                        # We can't use blank object or it will inject unwanted data, so null is used instead.
      minute_metrics = optional(object({
        enabled               = optional(bool, false)  # Indicates whether minute metrics are enabled. Defaults to false.
        include_apis          = optional(bool, null)   # Indicates whether APIs are included in the metrics. Defaults to null for resource default of null (unconfirmed).
        retention_policy_days = optional(number, null) # Number of days to retain metrics. Defaults to null for resource default of null (retention disabled).
        version               = string                 # The version of Storage Analytics to use. Possible values include: "1.0", "2.0", "2.1", "2.2", "2.3", "2015-02-21", "2017-04-17", "2018-03-28".
      }), null)                                        # We can't use blank object or it will inject unwanted data, so null is used instead.
    }), null)                                          # We can't use blank object or it will inject unwanted data, so null is used instead.

    ### Retention/Security

    allowed_copy_scope = optional(string, null) # Restrict copy to/from within AAD tenant or Private Links to same VNet. AAD, PrivateLink.
    customer_managed_key = optional(object({
      key_vault_key_id          = string                     # The ID of the Key Vault key.
      managed_hsm_key_id        = optional(string, null)     # The ID of the Managed HSM key. Defaults to null for resource default of null (key vault key will be used).
      user_assigned_identity_id = string                     # The ID of the User Assigned Managed Identity used to access the Key Vault.
    }), null)                                                # We can't use blank object or it will inject unwanted data, so null is used instead.
    https_traffic_only_enabled        = optional(bool, true) # Enforces HTTPS traffic only. Defaults to true.
    infrastructure_encryption_enabled = optional(bool, true) # Enables additional encryption at the infrastructure level. Service level is already encrypted. Defaults to true.
    immutability_policy = optional(object({
      allow_protected_append_writes = bool      # Allows protected append writes.
      period_since_creation_in_days = number    # The immutability period since creation in days.
      state                         = string    # Locked, Unlocked.
    }), null)                                   # We can't use blank object or it will inject unwanted data, so null is used instead.
    local_user_enabled = optional(bool, false)  # Enables local users for SFTP. Defaults to false.
    min_tls_version    = optional(string, null) # TLS1_0, TLS1_1, TLS1_2. Defaults to null for resource default of TLS1_2 for new storage accounts.
    sas_policy = optional(object({
      expiration_action = optional(string, null) # Log, Block. Defaults to null for resource default of Log.
      expiration_period = number                 # The number of days until the SAS policy expires.

    }), null)                                          # We can't use blank object or it will inject unwanted data, so null is used instead.
    table_encryption_key_type = optional(string, null) # Account, Service. Defaults to null for resource default of Service.
    queue_encryption_key_type = optional(string, null) # Account, Service. Defaults to null for resource default of Service.

    ###### Sub-resource & Additional Modules
    # Since parent is known, these can be created here, which makes it easier for users.
    # We don't specify the type here because the module itself will validate the structure. See the module variables for details for configuration.
    #
    # WARNING: Moving these resources to it's direct module will require recreation or state file manipulation.

    monitor_diagnostic_settings       = optional(any, []) # Main storage account settings. This is only for basic log analytics integration, at this time.
    monitor_diagnostic_settings_blob  = optional(any, []) # Sub-resource blob settings. This is only for basic log analytics integration, at this time.
    monitor_diagnostic_settings_file  = optional(any, []) # Sub-resource file settings. This is only for basic log analytics integration, at this time.
    monitor_diagnostic_settings_table = optional(any, []) # Sub-resource table settings. This is only for basic log analytics integration, at this time.
    monitor_diagnostic_settings_queue = optional(any, []) # Sub-resource queue settings. This is only for basic log analytics integration, at this time.
    role_assignments                  = optional(any, [])
    storage_containers                = optional(any, [])
    storage_management_policies       = optional(any, [])
  }))
}
