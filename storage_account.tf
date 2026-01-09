### Requirements:

terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.54.0" # Tested on this provider version, but will allow future patch versions.
    }
  }
  required_version = "~> 1.14.0" # Tested on this Terraform CLI version, but will allow future patch versions.
}

### Data:

### Resources:

###### Main

resource "azurerm_storage_account" "this" {
  for_each = local.storage_accounts

  ### Basic

  access_tier              = each.value.access_tier
  account_kind             = each.value.account_kind
  account_replication_type = each.value.account_replication_type
  account_tier             = each.value.account_tier
  dns_endpoint_type        = each.value.dns_endpoint_type
  edge_zone                = each.value.edge_zone
  large_file_share_enabled = each.value.large_file_share_enabled
  location                 = each.value.location
  is_hns_enabled           = each.value.is_hns_enabled
  name                     = each.value.name
  nfsv3_enabled            = each.value.nfsv3_enabled
  resource_group_name      = each.value.resource_group_name
  dynamic "static_website" {
    for_each = each.value.static_website
    content {
      index_document     = static_website.value.index_document
      error_404_document = static_website.value.error_404_document
    }
  }
  tags = each.value.tags

  ### Access

  allow_nested_items_to_be_public = each.value.allow_nested_items_to_be_public
  dynamic "azure_files_authentication" {
    for_each = each.value.azure_files_authentication
    content {
      dynamic "active_directory" {
        for_each = azure_files_authentication.value.active_directory
        content {
          domain_guid         = active_directory.value.domain_guid
          domain_name         = active_directory.value.domain_name
          domain_sid          = active_directory.value.domain_sid
          forest_name         = active_directory.value.forest_name
          netbios_domain_name = active_directory.value.netbios_domain_name
          storage_sid         = active_directory.value.storage_sid
        }
      }
      default_share_level_permission = azure_files_authentication.value.default_share_level_permission
      directory_type                 = azure_files_authentication.value.directory_type
    }
  }
  dynamic "custom_domain" {
    for_each = each.value.custom_domain
    content {
      name          = custom_domain.value.name
      use_subdomain = custom_domain.value.use_subdomain
    }
  }
  default_to_oauth_authentication = each.value.default_to_oauth_authentication
  dynamic "identity" {
    for_each = each.value.identity
    content {
      type         = identity.value.type
      identity_ids = identity.value.identity_ids
    }
  }
  public_network_access_enabled = each.value.public_network_access_enabled
  dynamic "routing" {
    for_each = each.value.routing
    content {
      choice                      = routing.value.choice
      publish_internet_endpoints  = routing.value.publish_internet_endpoints
      publish_microsoft_endpoints = routing.value.publish_microsoft_endpoints
    }
  }
  sftp_enabled              = each.value.sftp_enabled
  shared_access_key_enabled = each.value.shared_access_key_enabled

  ### Network

  dynamic "network_rules" {
    for_each = each.value.network_rules
    content {
      default_action = network_rules.value.default_action
      bypass         = network_rules.value.bypass
      ip_rules       = network_rules.value.ip_rules
      dynamic "private_link_access" {
        for_each = network_rules.value.private_link_access
        content {
          endpoint_resource_id = private_link_access.value.endpoint_resource_id
          endpoint_tenant_id   = private_link_access.value.endpoint_tenant_id
        }
      }
      virtual_network_subnet_ids = network_rules.value.virtual_network_subnet_ids
    }
  }

  ### Properties

  dynamic "blob_properties" {
    for_each = each.value.blob_properties
    content {
      change_feed_enabled           = blob_properties.value.change_feed_enabled
      change_feed_retention_in_days = blob_properties.value.change_feed_retention_in_days
      dynamic "container_delete_retention_policy" {
        for_each = blob_properties.value.container_delete_retention_policy
        content {
          days = container_delete_retention_policy.value.days
        }
      }
      dynamic "cors_rule" {
        for_each = blob_properties.value.cors_rule
        content {
          allowed_headers    = cors_rule.value.allowed_headers
          allowed_methods    = cors_rule.value.allowed_methods
          allowed_origins    = cors_rule.value.allowed_origins
          exposed_headers    = cors_rule.value.exposed_headers
          max_age_in_seconds = cors_rule.value.max_age_in_seconds
        }
      }
      default_service_version = blob_properties.value.default_service_version
      dynamic "delete_retention_policy" {
        for_each = blob_properties.value.delete_retention_policy
        content {
          days                     = delete_retention_policy.value.days
          permanent_delete_enabled = delete_retention_policy.value.permanent_delete_enabled
        }
      }
      last_access_time_enabled = blob_properties.value.last_access_time_enabled
      dynamic "restore_policy" {
        for_each = blob_properties.value.restore_policy
        content {
          days = restore_policy.value.days
        }
      }
      versioning_enabled = blob_properties.value.versioning_enabled
    }
  }

  dynamic "share_properties" {
    for_each = each.value.share_properties
    content {
      dynamic "cors_rule" {
        for_each = share_properties.value.cors_rule
        content {
          allowed_headers    = cors_rule.value.allowed_headers
          allowed_methods    = cors_rule.value.allowed_methods
          allowed_origins    = cors_rule.value.allowed_origins
          exposed_headers    = cors_rule.value.exposed_headers
          max_age_in_seconds = cors_rule.value.max_age_in_seconds
        }
      }
      dynamic "retention_policy" {
        for_each = share_properties.value.retention_policy
        content {
          days = retention_policy.value.days
        }
      }
      dynamic "smb" {
        for_each = share_properties.value.smb
        content {
          authentication_types            = smb.value.authentication_types
          channel_encryption_type         = smb.value.channel_encryption_type
          kerberos_ticket_encryption_type = smb.value.kerberos_ticket_encryption_type
          multichannel_enabled            = smb.value.multichannel_enabled
          versions                        = smb.value.versions
        }
      }
    }
  }

  dynamic "queue_properties" {
    for_each = each.value.queue_properties
    content {
      dynamic "cors_rule" {
        for_each = queue_properties.value.cors_rule
        content {
          allowed_headers    = cors_rule.value.allowed_headers
          allowed_methods    = cors_rule.value.allowed_methods
          allowed_origins    = cors_rule.value.allowed_origins
          exposed_headers    = cors_rule.value.exposed_headers
          max_age_in_seconds = cors_rule.value.max_age_in_seconds
        }
      }
      dynamic "logging" {
        for_each = queue_properties.value.logging
        content {
          delete                = logging.value.delete
          read                  = logging.value.read
          write                 = logging.value.write
          version               = logging.value.version
          retention_policy_days = logging.value.retention_policy_days
        }
      }
      dynamic "minute_metrics" {
        for_each = queue_properties.value.minute_metrics
        content {
          enabled               = minute_metrics.value.enabled
          include_apis          = minute_metrics.value.include_apis
          retention_policy_days = minute_metrics.value.retention_policy_days
          version               = minute_metrics.value.version
        }
      }
      dynamic "hour_metrics" {
        for_each = queue_properties.value.hour_metrics
        content {
          enabled               = hour_metrics.value.enabled
          include_apis          = hour_metrics.value.include_apis
          retention_policy_days = hour_metrics.value.retention_policy_days
          version               = hour_metrics.value.version
        }
      }
    }
  }

  ### Retention/Security

  allowed_copy_scope = each.value.allowed_copy_scope
  dynamic "customer_managed_key" {
    for_each = each.value.customer_managed_key
    content {
      key_vault_key_id          = customer_managed_key.value.key_vault_key_id
      managed_hsm_key_id        = customer_managed_key.value.managed_hsm_key_id
      user_assigned_identity_id = customer_managed_key.value.user_assigned_identity_id
    }
  }
  https_traffic_only_enabled        = each.value.https_traffic_only_enabled
  infrastructure_encryption_enabled = each.value.infrastructure_encryption_enabled
  dynamic "immutability_policy" {
    for_each = each.value.immutability_policy
    content {
      allow_protected_append_writes = immutability_policy.value.allow_protected_append_writes
      period_since_creation_in_days = immutability_policy.value.period_since_creation_in_days
      state                         = immutability_policy.value.state
    }
  }
  local_user_enabled = each.value.local_user_enabled
  min_tls_version    = each.value.min_tls_version
  dynamic "sas_policy" {
    for_each = each.value.sas_policy
    content {
      expiration_action = sas_policy.value.expiration_action
      expiration_period = sas_policy.value.expiration_period
    }
  }
  table_encryption_key_type = each.value.table_encryption_key_type
  queue_encryption_key_type = each.value.queue_encryption_key_type
}

###### Sub-resource & Additional Modules

module "lupus_az_monitor_diagnostic_setting" {
  depends_on = [azurerm_storage_account.this] # Ensures resource group exists before role assignments are created.
  source  = "lupusllc/monitor-diagnostic-setting/azurerm" # https://registry.terraform.io/modules/lupusllc/monitor-diagnostic-setting/azurerm/latest
  version = "0.0.1"

  ### Basic

  configuration               = var.configuration
  monitor_diagnostic_settings = local.monitor_diagnostic_settings
}

module "lupus_az_role_assignment" {
  depends_on = [azurerm_storage_account.this] # Ensures resource group exists before role assignments are created.
  source  = "lupusllc/role-assignment/azurerm" # https://registry.terraform.io/modules/lupusllc/role-assignment/azurerm/latest
  version = "0.0.3"

  ### Basic

  role_assignments = local.role_assignments
}

module "lupus_az_storage_container" {
  depends_on = [azurerm_storage_account.this] # Ensures resource group exists before role assignments are created.
  source  = "lupusllc/storage-container/azurerm" # https://registry.terraform.io/modules/lupusllc/storage-container/azurerm/latest
  version = "0.0.3"

  ### Basic

  configuration      = var.configuration
  storage_containers = local.storage_containers
}

module "lupus_az_storage_management_policy" {
  depends_on = [azurerm_storage_account.this] # Ensures resource group exists before role assignments are created.
  source  = "lupusllc/storage-management-policy/azurerm" # https://registry.terraform.io/modules/lupusllc/storage-management-policy/azurerm/latest
  version = "0.0.3"

  ### Basic

  configuration               = var.configuration
  storage_management_policies = local.storage_management_policies
}
