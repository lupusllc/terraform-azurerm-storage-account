# Helps to combine data, easier debug and remove complexity in the main resource.

locals {
  storage_accounts_list = [
    for index, storage_account in var.storage_accounts : {
      # Most will try and use key/value storage_account first, then try applicable defaults and then null as a last resort.
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
      static_website           = storage_account.static_website
      # Merges storage_account or default tags with required tags.
      tags = merge(
        # Count storage_account tags, if greater than 0 use them, otherwise try defaults tags if they exist, if not use a blank map. 
        length(storage_account.tags) > 0 ? storage_account.tags : try(var.defaults.tags, {}),
        try(var.required.tags, {})
      )

      ### Access

      allow_nested_items_to_be_public = storage_account.allow_nested_items_to_be_public
      azure_files_authentication      = storage_account.azure_files_authentication
      custom_domain                   = storage_account.custom_domain
      default_to_oauth_authentication = storage_account.default_to_oauth_authentication
      identity                        = storage_account.identity
      public_network_access_enabled   = storage_account.public_network_access_enabled
      routing                         = storage_account.routing
      sftp_enabled                    = storage_account.sftp_enabled
      shared_access_key_enabled       = storage_account.shared_access_key_enabled

      ### Network

      # Iterate through network_rules.
      network_rules = [for index, rule in storage_account.network_rules : {
        bypass              = rule.bypass
        default_action      = rule.default_action
        ip_rules            = rule.ip_rules
        private_link_access = rule.private_link_access

        # Iterate through virtual_network_subnets to build out subnet IDs.
        virtual_network_subnet_ids = [for item in rule.virtual_network_subnets :
          # If virtual_network_subnet_id is provided, use it directly.
          item.virtual_network_subnet_id != null ? item.virtual_network_subnet_id : (
            # Otherwise, if virtual network ID and subnet name are provided, construct the subnet ID.
            item.virtual_network_id != null && item.virtual_network_subnet_name != null ? format(
              "%s/subnets/%s",
              item.virtual_network_id,
              item.virtual_network_subnet_name
            ) :
            # Otherwise, construct the subnet ID from the subscription, virtual network name, resource group name, subnet name.
            format(
              "/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/virtualNetworks/%s/subnets/%s",
              var.configuration.subscription_id,
              item.virtual_network_resource_group_name,
              item.virtual_network_name,
            item.virtual_network_subnet_name)
          )
        ]
      }]

      ### Properties

      blob_properties  = storage_account.blob_properties
      share_properties = storage_account.share_properties
      queue_properties = storage_account.queue_properties

      ### Retention/Security

      allowed_copy_scope                = storage_account.allowed_copy_scope
      customer_managed_key              = storage_account.customer_managed_key
      https_traffic_only_enabled        = storage_account.https_traffic_only_enabled
      infrastructure_encryption_enabled = storage_account.infrastructure_encryption_enabled
      immutability_policy               = storage_account.immutability_policy
      local_user_enabled                = storage_account.local_user_enabled
      min_tls_version                   = storage_account.min_tls_version
      sas_policy                        = storage_account.sas_policy
      table_encryption_key_type         = storage_account.table_encryption_key_type
      queue_encryption_key_type         = storage_account.queue_encryption_key_type

      ###### Sub-resource & Additional Modules

      role_assignments            = storage_account.role_assignments
      storage_containers          = storage_account.storage_containers
      storage_management_policies = storage_account.storage_management_policies
    }
  ]

  # Used to create unique id for for_each loops, as just using the name may not be unique.
  storage_accounts = {
    for storage_account in local.storage_accounts_list : "${storage_account.resource_group_name}>${storage_account.name}" => storage_account
  }

  ### Sub-resource & Additional Modules

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
