# Deploying AuditLens Dashboard to Azure App Service

## Prerequisites

- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli) installed and logged in (`az login`)
- [Docker](https://www.docker.com/) installed locally
- An Azure subscription

---

## Step 1 — Create Azure resources

```bash
# Variables — change these to your values
RESOURCE_GROUP=rg-auditlens
LOCATION=eastus
ACR_NAME=auditlensacr           # must be globally unique, lowercase, no hyphens
APP_PLAN=plan-auditlens
APP_NAME=auditlens-dashboard    # becomes https://auditlens-dashboard.azurewebsites.net
STORAGE_ACCOUNT=auditlensstore  # globally unique, lowercase, no hyphens

# Resource group
az group create --name $RESOURCE_GROUP --location $LOCATION

# Azure Container Registry (stores the Docker image)
az acr create \
  --resource-group $RESOURCE_GROUP \
  --name $ACR_NAME \
  --sku Basic \
  --admin-enabled true

# App Service Plan (Linux, B1 = ~$13/month)
az appservice plan create \
  --name $APP_PLAN \
  --resource-group $RESOURCE_GROUP \
  --is-linux \
  --sku B1

# Azure Files share for persistent SQLite storage
az storage account create \
  --name $STORAGE_ACCOUNT \
  --resource-group $RESOURCE_GROUP \
  --location $LOCATION \
  --sku Standard_LRS

az storage share create \
  --name auditlens-data \
  --account-name $STORAGE_ACCOUNT
```

---

## Step 2 — Build and push the Docker image to ACR

```bash
# Log in to ACR
az acr login --name $ACR_NAME

# Build and push (from the AuditLens repo root)
IMAGE="${ACR_NAME}.azurecr.io/auditlens:latest"

docker build -t $IMAGE .
docker push $IMAGE
```

---

## Step 3 — Create the Web App

```bash
# Get ACR credentials
ACR_PASSWORD=$(az acr credential show --name $ACR_NAME --query "passwords[0].value" -o tsv)

# Create the Web App from the container
az webapp create \
  --resource-group $RESOURCE_GROUP \
  --plan $APP_PLAN \
  --name $APP_NAME \
  --deployment-container-image-name $IMAGE \
  --docker-registry-server-url "https://${ACR_NAME}.azurecr.io" \
  --docker-registry-server-user $ACR_NAME \
  --docker-registry-server-password $ACR_PASSWORD
```

---

## Step 4 — Mount persistent storage for SQLite

```bash
STORAGE_KEY=$(az storage account keys list \
  --resource-group $RESOURCE_GROUP \
  --account-name $STORAGE_ACCOUNT \
  --query "[0].value" -o tsv)

az webapp config storage-account add \
  --resource-group $RESOURCE_GROUP \
  --name $APP_NAME \
  --custom-id auditlens-data \
  --storage-type AzureFiles \
  --share-name auditlens-data \
  --account-name $STORAGE_ACCOUNT \
  --access-key $STORAGE_KEY \
  --mount-path /data/db
```

---

## Step 5 — Set environment variables (secrets)

```bash
az webapp config appsettings set \
  --resource-group $RESOURCE_GROUP \
  --name $APP_NAME \
  --settings \
    AUDITLENS_USER="admin" \
    AUDITLENS_PASSWORD="<choose-a-strong-password>" \
    AUDITLENS_DB="/data/db/history.db" \
    SCAN_PATH="/data/scan" \
    SCAN_FIRST="true" \
    WEB_CONCURRENCY="2" \
    WEBSITES_PORT="8080"
```

> **Important**: Replace `<choose-a-strong-password>` with a real password.
> Never commit credentials to git.

---

## Step 6 — Open the dashboard

```bash
az webapp browse --name $APP_NAME --resource-group $RESOURCE_GROUP
```

URL: `https://<APP_NAME>.azurewebsites.net`

The browser will prompt for the username and password you set in Step 5.

---

## Scanning a project

The container expects the project to scan at `/data/scan`. There are two options:

### Option A — Scan a repo by cloning it at startup

Add a startup command that clones the repo before starting gunicorn:

```bash
az webapp config set \
  --resource-group $RESOURCE_GROUP \
  --name $APP_NAME \
  --startup-file "git clone https://github.com/your-org/your-repo /data/scan && docker-entrypoint.sh"
```

### Option B — Upload/sync code to the Azure Files share

Mount the Azure Files share locally and copy files into `auditlens-data/`:

```bash
# macOS/Linux via SMB
STORAGE_KEY=$(az storage account keys list \
  --resource-group $RESOURCE_GROUP \
  --account-name $STORAGE_ACCOUNT \
  --query "[0].value" -o tsv)

az storage file upload-batch \
  --account-name $STORAGE_ACCOUNT \
  --account-key $STORAGE_KEY \
  --destination auditlens-data \
  --source /path/to/your/project
```

---

## Updating the image

```bash
docker build -t $IMAGE .
docker push $IMAGE
az webapp restart --name $APP_NAME --resource-group $RESOURCE_GROUP
```

Or enable continuous deployment from ACR:

```bash
az webapp deployment container config \
  --enable-cd true \
  --name $APP_NAME \
  --resource-group $RESOURCE_GROUP
```

---

## Cost estimate (B1 App Service Plan)

| Resource | Approx. monthly cost |
|---|---|
| App Service Plan B1 | ~$13 USD |
| Azure Container Registry Basic | ~$5 USD |
| Azure Files (5 GB) | ~$0.10 USD |
| **Total** | **~$18 USD/month** |

---

## Local testing before deploying

```bash
docker compose up --build
# Dashboard at http://localhost:8080  (user: admin / changeme)
```
