output "storage_accounts" {
  description = "The Storage Accounts."
  value       = azurerm_storage_account.this
}

### Debug Only

output "var_storage_accounts" {
  value = var.storage_accounts
}

output "local_storage_accounts" {
  value = local.storage_accounts
}
