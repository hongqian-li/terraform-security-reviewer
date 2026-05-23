# ============================================================
# sample_bad_azure.tf — intentionally insecure Azure config
# for use as a test fixture. DO NOT use in production.
# ============================================================

# AZ-STG-001: Storage account with public blob access enabled
resource "azurerm_storage_account" "bad_storage" {
  name                     = "mybadstorageaccount"
  resource_group_name      = "my-rg"
  location                 = "westeurope"
  account_tier             = "Standard"
  account_replication_type = "LRS"

  # Allows anonymous public read access to blobs
  allow_nested_items_to_be_public = true
}

# AZ-NSG-001: Network security group rule open to the entire internet
resource "azurerm_network_security_rule" "allow_all_inbound" {
  name                        = "allow-all-inbound"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = "my-rg"
  network_security_group_name = "my-nsg"
}

# AZ-SQL-001: SQL Server with public network access and low TLS
resource "azurerm_mssql_server" "bad_sql" {
  name                         = "my-bad-sql-server"
  resource_group_name          = "my-rg"
  location                     = "westeurope"
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = "BadPassword123!"  # SEC-001: hardcoded password
  minimum_tls_version          = "Disabled"
  public_network_access_enabled = true
}

# AZ-KV-001: Key Vault without purge protection
resource "azurerm_key_vault" "bad_kv" {
  name                = "my-bad-keyvault"
  location            = "westeurope"
  resource_group_name = "my-rg"
  tenant_id           = "00000000-0000-0000-0000-000000000000"
  sku_name            = "standard"

  # purge_protection_enabled not set — secrets can be permanently deleted immediately
  soft_delete_retention_days = 7
}

# AZ-APP-001: App Service without HTTPS enforcement
resource "azurerm_linux_web_app" "bad_app" {
  name                = "my-bad-web-app"
  resource_group_name = "my-rg"
  location            = "westeurope"
  service_plan_id     = "/subscriptions/xxx/resourceGroups/my-rg/providers/Microsoft.Web/serverfarms/my-plan"

  https_only = false  # allows unencrypted HTTP traffic

  site_config {}
}
