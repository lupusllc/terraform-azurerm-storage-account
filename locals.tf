# Helps to combine data, easier debug and remove complexity in the main resource.

locals {
  storage_accounts_list = [
    for index, settings in var.storage_accounts : {
      # Most will try and use key/value settings first, then try applicable defaults and then null as a last resort.
      ### Basic

      access_tier              = settings.access_tier
      account_kind             = settings.account_kind
      account_replication_type = settings.account_replication_type
      account_tier             = settings.account_tier
      dns_endpoint_type        = settings.dns_endpoint_type
      edge_zone                = settings.edge_zone
      large_file_share_enabled = settings.large_file_share_enabled
      location                 = try(coalesce(settings.location, try(var.defaults.location, null)), null)
      index                    = index # Added in case it's ever needed, since for_each/for loops don't have inherent indexes.
      is_hns_enabled           = settings.is_hns_enabled
      name                     = settings.name
      nfsv3_enabled            = settings.nfsv3_enabled
      resource_group_name      = try(coalesce(settings.resource_group_name, try(var.defaults.resource_group_name, null)), null)
      static_website           = settings.static_website
      # Merges settings or default tags with required tags.
      tags = merge(
        # Count settings tags, if greater than 0 use them, otherwise try defaults tags if they exist, if not use a blank map. 
        length(settings.tags) > 0 ? settings.tags : try(var.defaults.tags, {}),
        try(var.required.tags, {})
      )

      ### Access

      allow_nested_items_to_be_public = settings.allow_nested_items_to_be_public
      azure_files_authentication      = settings.azure_files_authentication
      custom_domain                   = settings.custom_domain
      default_to_oauth_authentication = settings.default_to_oauth_authentication
      identity                        = settings.identity
      public_network_access_enabled   = settings.public_network_access_enabled
      routing                         = settings.routing
      sftp_enabled                    = settings.sftp_enabled
      shared_access_key_enabled       = settings.shared_access_key_enabled

      ### Network

      # Iterate through network_rules.
      network_rules = [for index, rule in settings.network_rules : {
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
              data.azurerm_client_config.current.subscription_id,
              item.virtual_network_resource_group_name,
              item.virtual_network_name,
            item.virtual_network_subnet_name)
          )
        ]
      }]

      ### Properties

      blob_properties  = settings.blob_properties
      share_properties = settings.share_properties
      queue_properties = settings.queue_properties

      ### Retention/Security

      allowed_copy_scope                = settings.allowed_copy_scope
      customer_managed_key              = settings.customer_managed_key
      https_traffic_only_enabled        = settings.https_traffic_only_enabled
      infrastructure_encryption_enabled = settings.infrastructure_encryption_enabled
      immutability_policy               = settings.immutability_policy
      local_user_enabled                = settings.local_user_enabled
      min_tls_version                   = settings.min_tls_version
      sas_policy                        = settings.sas_policy
      table_encryption_key_type         = settings.table_encryption_key_type
      queue_encryption_key_type         = settings.queue_encryption_key_type
    }
  ]

  # Used to create unique id for for_each loops, as just using the name may not be unique.
  storage_accounts = {
    for index, settings in local.storage_accounts_list : "${settings.resource_group_name}>${settings.name}" => settings
  }
}