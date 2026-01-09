# Helps to combine data, easier debug and remove complexity in the main resource.

locals {
  storage_accounts_list = [
    for index, storage_account in var.storage_accounts : {
      # Most will try and use key/value storage_account first, then try applicable defaults and then null as a last resort.

      # There are dozens of objects that are going to be encased in a list for dynamic block requirements, despite always being a single item.
      # The input variable is not required to be in a list for a better user experience since it's not needed or logical.
      # Since there are so many, we're not going to add this same comment throughout. Watch for "Dynamic Block:" comments.

      ### Basic

      access_tier              = storage_account.access_tier
      account_kind             = storage_account.account_kind
      account_replication_type = storage_account.account_replication_type
      account_tier             = storage_account.account_tier
      dns_endpoint_type        = storage_account.dns_endpoint_type
      edge_zone                = storage_account.edge_zone
      large_file_share_enabled = storage_account.large_file_share_enabled
      location                 = try(coalesce(storage_account.location, try(var.defaults.location, null)), null)
      index                    = index # Added in case it's ever needed, since for_each/for loops don't have inherent indexes.
      is_hns_enabled           = storage_account.is_hns_enabled
      name                     = storage_account.name
      nfsv3_enabled            = storage_account.nfsv3_enabled
      resource_group_name      = try(coalesce(storage_account.resource_group_name, try(var.defaults.resource_group_name, null)), null)
      static_website           = storage_account.static_website == null ? [] : [storage_account.static_website] # Dynamic block: If object is null, provide an empty list. Otherwise, make a list of the object.

      # Merges storage_account or default tags with required tags.
      tags = merge(
        # Count storage_account tags, if greater than 0 use them, otherwise try defaults tags if they exist, if not use a blank map. 
        length(storage_account.tags) > 0 ? storage_account.tags : try(var.defaults.tags, {}),
        try(var.required.tags, {})
      )

      ### Access

      allow_nested_items_to_be_public = storage_account.allow_nested_items_to_be_public
      # Dynamic block: If object is null, provide an empty list. Otherwise, make a list of the merged object with a nested dynamic.
      azure_files_authentication = storage_account.azure_files_authentication == null ? [] : [merge(storage_account.azure_files_authentication, {
        # Nested Dynamic block: If object is null, provide an empty list. Otherwise, make a list of the object.
        active_directory = storage_account.azure_files_authentication.active_directory == null ? [] : [storage_account.azure_files_authentication.active_directory]
      })]
      custom_domain                   = storage_account.custom_domain == null ? [] : [storage_account.custom_domain] # Dynamic block: If object is null, provide an empty list. Otherwise, make a list of the object.
      default_to_oauth_authentication = storage_account.default_to_oauth_authentication
      identity                        = storage_account.identity == null ? [] : [storage_account.identity] # Dynamic block: If object is null, provide an empty list. Otherwise, make a list of the object.
      public_network_access_enabled   = storage_account.public_network_access_enabled
      routing                         = storage_account.routing == null ? [] : [storage_account.routing] # Dynamic block: If object is null, provide an empty list. Otherwise, make a list of the object.
      sftp_enabled                    = storage_account.sftp_enabled
      shared_access_key_enabled       = storage_account.shared_access_key_enabled

      ### Network

      # If object is null, provide an empty list. Otherwise, make a list of the object with the following changes.
      # In this case, we're listing out all variables so we can filter out ones not used by the resource, just in case.
      network_rules = storage_account.network_rules == null ? [] : [{
        bypass              = storage_account.network_rules.bypass
        default_action      = storage_account.network_rules.default_action
        ip_rules            = storage_account.network_rules.ip_rules
        private_link_access = storage_account.network_rules.private_link_access # Dynamic block: This can have more than one item, so it's expected to be a list already.

        # Iterate through virtual_network_subnets to build out subnet IDs.
        virtual_network_subnet_ids = [for subnet in storage_account.network_rules.virtual_network_subnets :
          # If virtual_network_subnet_id is provided, use it directly.
          subnet.virtual_network_subnet_id != null ? subnet.virtual_network_subnet_id : (
            # Otherwise, if virtual network ID and subnet name are provided, construct the subnet ID.
            subnet.virtual_network_id != null && subnet.virtual_network_subnet_name != null ? format(
              "%s/subnets/%s",
              subnet.virtual_network_id,
              subnet.virtual_network_subnet_name
            ) :
            # Otherwise, construct the subnet ID from the subscription, virtual network name, resource group name, subnet name.
            format(
              "/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/virtualNetworks/%s/subnets/%s",
              var.configuration.subscription_id,
              subnet.virtual_network_resource_group_name,
              subnet.virtual_network_name,
              subnet.virtual_network_subnet_name
            )
          )
        ]
      }]

      ### Properties

      # Dynamic block: If object is null, provide an empty list. Otherwise, make a list of the merged object with a nested dynamic.
      blob_properties = storage_account.blob_properties == null ? [] : [merge(storage_account.blob_properties, {
        # Nested Dynamic blocks: If object is null, provide an empty list. Otherwise, make a list of the object.
        container_delete_retention_policy = storage_account.blob_properties.container_delete_retention_policy == null ? [] : [storage_account.blob_properties.container_delete_retention_policy]
        cors_rule                         = storage_account.blob_properties.cors_rule == null ? [] : [storage_account.blob_properties.cors_rule]
        delete_retention_policy           = storage_account.blob_properties.delete_retention_policy == null ? [] : [storage_account.blob_properties.delete_retention_policy]
        restore_policy                    = storage_account.blob_properties.restore_policy == null ? [] : [storage_account.blob_properties.restore_policy]
      })]

      # Dynamic block: If object is null, provide an empty list. Otherwise, make a list of the merged object with a nested dynamic.
      share_properties = storage_account.share_properties == null ? [] : [merge(storage_account.share_properties, {
        # Nested Dynamic blocks: If object is null, provide an empty list. Otherwise, make a list of the object.
        container_delete_retention_policy = storage_account.share_properties.container_delete_retention_policy == null ? [] : [storage_account.share_properties.container_delete_retention_policy]
        retention_policy                  = storage_account.share_properties.retention_policy == null ? [] : [storage_account.share_properties.retention_policy]
        smb                               = storage_account.share_properties.smb == null ? [] : [storage_account.share_properties.smb]
      })]

      # Dynamic block: If object is null, provide an empty list. Otherwise, make a list of the merged object with a nested dynamic.
      queue_properties = storage_account.queue_properties == null ? [] : [merge(storage_account.queue_properties, {
        # Nested Dynamic blocks: If object is null, provide an empty list. Otherwise, make a list of the object.
        cors_rule      = storage_account.queue_properties.cors_rule == null ? [] : [storage_account.queue_properties.cors_rule]
        hour_metrics   = storage_account.queue_properties.hour_metrics == null ? [] : [storage_account.queue_properties.hour_metrics]
        logging        = storage_account.queue_properties.logging == null ? [] : [storage_account.queue_properties.logging]
        minute_metrics = storage_account.queue_properties.minute_metrics == null ? [] : [storage_account.queue_properties.minute_metrics]
      })]

      ### Retention/Security

      allowed_copy_scope                = storage_account.allowed_copy_scope
      customer_managed_key              = storage_account.customer_managed_key == null ? [] : [storage_account.customer_managed_key] # Dynamic block: If object is null, provide an empty list. Otherwise, make a list of the object.
      https_traffic_only_enabled        = storage_account.https_traffic_only_enabled
      infrastructure_encryption_enabled = storage_account.infrastructure_encryption_enabled
      immutability_policy               = storage_account.immutability_policy == null ? [] : [storage_account.immutability_policy] # Dynamic block: If object is null, provide an empty list. Otherwise, make a list of the object.
      local_user_enabled                = storage_account.local_user_enabled
      min_tls_version                   = storage_account.min_tls_version
      sas_policy                        = storage_account.sas_policy == null ? [] : [storage_account.sas_policy] # Dynamic block: If object is null, provide an empty list. Otherwise, make a list of the object.
      table_encryption_key_type         = storage_account.table_encryption_key_type
      queue_encryption_key_type         = storage_account.queue_encryption_key_type

      ###### Sub-resource & Additional Modules

      monitor_diagnostic_settings       = storage_account.monitor_diagnostic_settings
      monitor_diagnostic_settings_blob  = storage_account.monitor_diagnostic_settings_blob
      monitor_diagnostic_settings_file  = storage_account.monitor_diagnostic_settings_file
      monitor_diagnostic_settings_table = storage_account.monitor_diagnostic_settings_table
      monitor_diagnostic_settings_queue = storage_account.monitor_diagnostic_settings_queue
      role_assignments                  = storage_account.role_assignments
      storage_containers                = storage_account.storage_containers
      storage_management_policies       = storage_account.storage_management_policies
    }
  ]

  # Used to create unique id for for_each loops, as just using the name may not be unique.
  storage_accounts = {
    for storage_account in local.storage_accounts_list : "${storage_account.resource_group_name}>${storage_account.name}" => storage_account
  }

  ### Sub-resource & Additional Modules

  # Iterate local.storage_accounts_list and monitor_diagnostic_settings to build a flat list of monitor_diagnostic_settings with storage_account_name & storage_account_resource_group_name.
  monitor_diagnostic_settings_base = flatten([
    for storage_account in local.storage_accounts_list : [
      for monitor_diagnostic_setting in storage_account.monitor_diagnostic_settings : {
        # No options as of 1/7/2025 per data export of azurerm_monitor_diagnostic_categories, so this is an empty list. But this may change in the future.
        enabled_log = []
        # Check length of enabled_log and enabled_metric, if they don't exist set to zero. If both are zero, use a base default for the resource.
        enabled_metric = try(length(monitor_diagnostic_setting.enabled_log), 0) == 0 && try(length(monitor_diagnostic_setting.enabled_metric), 0) == 0 ? [
          # Options as of 1/7/2025 per data export of azurerm_monitor_diagnostic_categories.
          # Category: Capacity, Transaction
          { category = "Capacity" },
          { category = "Transaction" }
          # Otherwise, try and use what was provided. If nothing, a blank list.
        ] : try(monitor_diagnostic_setting.enabled_metric, [])
        log_analytics_workspace_id = format(
          "/subscriptions/%s/resourceGroups/%s/providers/Microsoft.OperationalInsights/workspaces/%s",
          var.configuration.subscription_id,
          monitor_diagnostic_setting.log_analytics_workspace_resource_group_name,
          monitor_diagnostic_setting.log_analytics_workspace_name
        )
        name                       = try(monitor_diagnostic_setting.name, null)
        target_name                = storage_account.name
        target_resource_group_name = storage_account.resource_group_name
        target_resource_id = format(
          "/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Storage/storageAccounts/%s",
          var.configuration.subscription_id,
          storage_account.resource_group_name,
          storage_account.name
        )
      }
    ] if length(storage_account.monitor_diagnostic_settings) > 0 # Filters out any empty storage container lists.
  ])

  # Iterate local.storage_accounts_list and monitor_diagnostic_settings_blob to build a flat list of monitor_diagnostic_settings_blob with storage_account_name & storage_account_resource_group_name.
  monitor_diagnostic_settings_blob = flatten([
    for storage_account in local.storage_accounts_list : [
      for monitor_diagnostic_setting in storage_account.monitor_diagnostic_settings_blob : {
        enabled_log = try(length(monitor_diagnostic_setting.enabled_log), 0) == 0 && try(length(monitor_diagnostic_setting.enabled_metric), 0) == 0 ? [
          # Options as of 1/7/2025 per data export of azurerm_monitor_diagnostic_categories all four match each other.
          # Log Category (Type): StorageDelete, StorageRead, StorageWrite
          # Log Category Group: allLogs, audit
          { category_group = "allLogs" }
        ] : try(monitor_diagnostic_setting.enabled_log, [])
        # Check length of enabled_log and enabled_metric, if they don't exist set to zero. If both are zero, use a base default for the resource.
        enabled_metric = try(length(monitor_diagnostic_setting.enabled_log), 0) == 0 && try(length(monitor_diagnostic_setting.enabled_metric), 0) == 0 ? [
          # Options as of 1/7/2025 per data export of azurerm_monitor_diagnostic_categories.
          # Category: Capacity, Transaction
          { category = "Capacity" },
          { category = "Transaction" }
          # Otherwise, try and use what was provided. If nothing, a blank list.
        ] : try(monitor_diagnostic_setting.enabled_metric, [])
        log_analytics_workspace_id = format(
          "/subscriptions/%s/resourceGroups/%s/providers/Microsoft.OperationalInsights/workspaces/%s",
          var.configuration.subscription_id,
          monitor_diagnostic_setting.log_analytics_workspace_resource_group_name,
          monitor_diagnostic_setting.log_analytics_workspace_name
        )
        name                       = try(monitor_diagnostic_setting.name, null)
        target_name                = storage_account.name
        target_resource_group_name = storage_account.resource_group_name
        target_resource_id = format(
          "/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Storage/storageAccounts/%s/blobServices/default",
          var.configuration.subscription_id,
          storage_account.resource_group_name,
          storage_account.name
        )
        target_sub_resource_path = "blobServices/default"
      }
    ] if length(storage_account.monitor_diagnostic_settings_blob) > 0 # Filters out any empty storage container lists.
  ])

  # Iterate local.storage_accounts_list and monitor_diagnostic_settings_file to build a flat list of monitor_diagnostic_settings_file with storage_account_name & storage_account_resource_group_name.
  monitor_diagnostic_settings_file = flatten([
    for storage_account in local.storage_accounts_list : [
      for monitor_diagnostic_setting in storage_account.monitor_diagnostic_settings_file : {
        enabled_log = try(length(monitor_diagnostic_setting.enabled_log), 0) == 0 && try(length(monitor_diagnostic_setting.enabled_metric), 0) == 0 ? [
          # Options as of 1/7/2025 per data export of azurerm_monitor_diagnostic_categories all four match each other.
          # Log Category (Type): StorageDelete, StorageRead, StorageWrite
          # Log Category Group: allLogs, audit
          { category_group = "allLogs" }
        ] : try(monitor_diagnostic_setting.enabled_log, [])
        # Check length of enabled_log and enabled_metric, if they don't exist set to zero. If both are zero, use a base default for the resource.
        enabled_metric = try(length(monitor_diagnostic_setting.enabled_log), 0) == 0 && try(length(monitor_diagnostic_setting.enabled_metric), 0) == 0 ? [
          # Options as of 1/7/2025 per data export of azurerm_monitor_diagnostic_categories.
          # Category: Capacity, Transaction
          { category = "Capacity" },
          { category = "Transaction" }
          # Otherwise, try and use what was provided. If nothing, a blank list.
        ] : try(monitor_diagnostic_setting.enabled_metric, [])
        log_analytics_workspace_id = format(
          "/subscriptions/%s/resourceGroups/%s/providers/Microsoft.OperationalInsights/workspaces/%s",
          var.configuration.subscription_id,
          monitor_diagnostic_setting.log_analytics_workspace_resource_group_name,
          monitor_diagnostic_setting.log_analytics_workspace_name
        )
        name                       = try(monitor_diagnostic_setting.name, null)
        target_name                = storage_account.name
        target_resource_group_name = storage_account.resource_group_name
        target_resource_id = format(
          "/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Storage/storageAccounts/%s/fileServices/default",
          var.configuration.subscription_id,
          storage_account.resource_group_name,
          storage_account.name
        )
        target_sub_resource_path = "fileServices/default"
      }
    ] if length(storage_account.monitor_diagnostic_settings_file) > 0 # Filters out any empty storage container lists.
  ])

  # Iterate local.storage_accounts_list and monitor_diagnostic_settings_table to build a flat list of monitor_diagnostic_settings_table with storage_account_name & storage_account_resource_group_name.
  monitor_diagnostic_settings_table = flatten([
    for storage_account in local.storage_accounts_list : [
      for monitor_diagnostic_setting in storage_account.monitor_diagnostic_settings_table : {
        enabled_log = try(length(monitor_diagnostic_setting.enabled_log), 0) == 0 && try(length(monitor_diagnostic_setting.enabled_metric), 0) == 0 ? [
          # Options as of 1/7/2025 per data export of azurerm_monitor_diagnostic_categories all four match each other.
          # Log Category (Type): StorageDelete, StorageRead, StorageWrite
          # Log Category Group: allLogs, audit
          { category_group = "allLogs" }
        ] : try(monitor_diagnostic_setting.enabled_log, [])
        # Check length of enabled_log and enabled_metric, if they don't exist set to zero. If both are zero, use a base default for the resource.
        enabled_metric = try(length(monitor_diagnostic_setting.enabled_log), 0) == 0 && try(length(monitor_diagnostic_setting.enabled_metric), 0) == 0 ? [
          # Options as of 1/7/2025 per data export of azurerm_monitor_diagnostic_categories.
          # Category: Capacity, Transaction
          { category = "Capacity" },
          { category = "Transaction" }
          # Otherwise, try and use what was provided. If nothing, a blank list.
        ] : try(monitor_diagnostic_setting.enabled_metric, [])
        log_analytics_workspace_id = format(
          "/subscriptions/%s/resourceGroups/%s/providers/Microsoft.OperationalInsights/workspaces/%s",
          var.configuration.subscription_id,
          monitor_diagnostic_setting.log_analytics_workspace_resource_group_name,
          monitor_diagnostic_setting.log_analytics_workspace_name
        )
        name                       = try(monitor_diagnostic_setting.name, null)
        target_name                = storage_account.name
        target_resource_group_name = storage_account.resource_group_name
        target_resource_id = format(
          "/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Storage/storageAccounts/%s/tableServices/default",
          var.configuration.subscription_id,
          storage_account.resource_group_name,
          storage_account.name
        )
        target_sub_resource_path = "tableServices/default"
      }
    ] if length(storage_account.monitor_diagnostic_settings_table) > 0 # Filters out any empty storage container lists.
  ])

  # Iterate local.storage_accounts_list and monitor_diagnostic_settings_queue to build a flat list of monitor_diagnostic_settings_queue with storage_account_name & storage_account_resource_group_name.
  monitor_diagnostic_settings_queue = flatten([
    for storage_account in local.storage_accounts_list : [
      for monitor_diagnostic_setting in storage_account.monitor_diagnostic_settings_queue : {
        enabled_log = try(length(monitor_diagnostic_setting.enabled_log), 0) == 0 && try(length(monitor_diagnostic_setting.enabled_metric), 0) == 0 ? [
          # Options as of 1/7/2025 per data export of azurerm_monitor_diagnostic_categories all four match each other.
          # Log Category (Type): StorageDelete, StorageRead, StorageWrite
          # Log Category Group: allLogs, audit
          { category_group = "allLogs" }
        ] : try(monitor_diagnostic_setting.enabled_log, [])
        # Check length of enabled_log and enabled_metric, if they don't exist set to zero. If both are zero, use a base default for the resource.
        enabled_metric = try(length(monitor_diagnostic_setting.enabled_log), 0) == 0 && try(length(monitor_diagnostic_setting.enabled_metric), 0) == 0 ? [
          # Options as of 1/7/2025 per data export of azurerm_monitor_diagnostic_categories.
          # Category: Capacity, Transaction
          { category = "Capacity" },
          { category = "Transaction" }
          # Otherwise, try and use what was provided. If nothing, a blank list.
        ] : try(monitor_diagnostic_setting.enabled_metric, [])
        log_analytics_workspace_id = format(
          "/subscriptions/%s/resourceGroups/%s/providers/Microsoft.OperationalInsights/workspaces/%s",
          var.configuration.subscription_id,
          monitor_diagnostic_setting.log_analytics_workspace_resource_group_name,
          monitor_diagnostic_setting.log_analytics_workspace_name
        )
        name                       = try(monitor_diagnostic_setting.name, null)
        target_name                = storage_account.name
        target_resource_group_name = storage_account.resource_group_name
        target_resource_id = format(
          "/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Storage/storageAccounts/%s/queueServices/default",
          var.configuration.subscription_id,
          storage_account.resource_group_name,
          storage_account.name
        )
        target_sub_resource_path = "queueServices/default"
      }
    ] if length(storage_account.monitor_diagnostic_settings_queue) > 0 # Filters out any empty storage container lists.
  ])

  # Combine all monitor_diagnostic_settings lists into one.
  monitor_diagnostic_settings = concat(
    local.monitor_diagnostic_settings_base,
    local.monitor_diagnostic_settings_blob,
    local.monitor_diagnostic_settings_file,
    local.monitor_diagnostic_settings_table,
    local.monitor_diagnostic_settings_queue
  )

  # Iterate local.storage_accounts_list and role_assignments to build a flat list of role_assignments with proper scope and unique IDs.
  role_assignments = flatten([
    for storage_account in local.storage_accounts_list : [
      for role_assignment in storage_account.role_assignments : merge(role_assignment, {
        scope = azurerm_storage_account.this["${storage_account.resource_group_name}>${storage_account.name}"].id
        unique_for_each_id = format(
          "%s>%s>%s>%s",
          storage_account.resource_group_name,
          storage_account.name,
          role_assignment.principal_id,
          coalesce(try(role_assignment.role_definition_name, null), try(role_assignment.role_definition_id, null))
        )
      })
    ] if length(storage_account.role_assignments) > 0 # Filters out any empty role assignment lists.
  ])

  # Iterate local.storage_accounts_list and storage_containers to build a flat list of storage_containers with storage_account_name & storage_account_resource_group_name.
  storage_containers = flatten([
    for storage_account in local.storage_accounts_list : [
      for storage_container in storage_account.storage_containers : merge(storage_container, {
        storage_account_name                = storage_account.name
        storage_account_resource_group_name = storage_account.resource_group_name
      })
    ] if length(storage_account.storage_containers) > 0 # Filters out any empty storage container lists.
  ])

  # Iterate local.storage_accounts_list and storage_management_policies to build a flat list of storage_management_policies with storage_account_name & storage_account_resource_group_name.
  storage_management_policies = flatten([
    for storage_account in local.storage_accounts_list : [
      for storage_management_policy in storage_account.storage_management_policies : merge(storage_management_policy, {
        storage_account_name                = storage_account.name
        storage_account_resource_group_name = storage_account.resource_group_name
      })
    ] if length(storage_account.storage_management_policies) > 0 # Filters out any empty storage container lists.
  ])
}
