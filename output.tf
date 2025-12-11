output "storage_accounts" {
  description = "The storage accounts."
  value       = azurerm_storage_account.this
}

### This needs reworked, it's giving us nested results. The same occurs with for loops.
output "storage_account_role_assignments" {
  description = "The storage account role assignments."
  value = merge(
    [
      for name, results in module.lupus_az_role_assignment : results.role_assignments
    ]... # Unpack the list of lists into a single list.
  )
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
