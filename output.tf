output "storage_accounts" {
  description = "The storage accounts."
  value       = azurerm_storage_account.this
}

output "storage_account_role_assignments" {
  description = "The storage account role assignments."
  value       = module.lupus_az_role_assignment.role_assignments
}

output "storage_account_storage_containers" {
  description = "The storage account storage containers."
  value       = module.lupus_az_storage_container.storage_containers
}

output "storage_account_storage_management_policies" {
  description = "The storage account storage management policies."
  value       = module.lupus_az_storage_management_policy.storage_management_policies
}

### Debug Only

output "var_storage_accounts" {
  value = var.storage_accounts
}

output "local_storage_accounts" {
  value = local.storage_accounts
}

output "local_storage_account_role_assignments" {
  value = local.role_assignments
}

output "local_storage_account_storage_containers" {
  value = local.storage_containers
}

output "local_storage_account_storage_management_policies" {
  value = local.storage_management_policies
}
