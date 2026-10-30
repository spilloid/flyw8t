<#
.SYNOPSIS
One-time setup: lets flyw8t's GitHub `release` environment sign Windows binaries with the
existing Azure Artifact Signing account.

.DESCRIPTION
Run once, by someone who owns the Azure subscription, signed in with `az login` and `gh auth login`.
It creates nothing broader than flyw8t needs:
  1. An app registration, `flyw8t-release-signing`, with no secret or password of its own.
  2. One federated credential, so only GitHub Actions jobs in spilloid/flyw8t's `release`
     environment can sign in as it (that environment is limited to `main` and `v*` tags).
  3. One role, "Artifact Signing Certificate Profile Signer", on the one certificate profile.
  4. The app's client ID as the `AZURE_CLIENT_ID` secret of that environment.
Undo: `az ad app delete --id <client id>` removes the identity, its credential and its role.

The other settings (tenant and subscription IDs, account, endpoint, profile, expected subject)
are already set on the environment. After this, run the Signing check workflow
(`gh workflow run signing-check.yml -R spilloid/flyw8t`) before tagging a release.
#>
$ErrorActionPreference = 'Stop'
$repo = 'spilloid/flyw8t'
$subject = 'repo:spilloid@19334728/flyw8t@1437979575:environment:release'
$profileScope = '/subscriptions/758f5ae0-a44e-4b93-9a94-15fd256593f2/resourceGroups/RG0/providers/Microsoft.CodeSigning/codeSigningAccounts/jdspille/certificateProfiles/primary-profile'

$appId = az ad app create --display-name flyw8t-release-signing --sign-in-audience AzureADMyOrg --query appId -o tsv
$spId = az ad sp create --id $appId --query id -o tsv
Write-Host "Created app $appId (service principal $spId)"

$fic = @{
    name        = 'github-release'
    issuer      = 'https://token.actions.githubusercontent.com'
    subject     = $subject
    audiences   = @('api://AzureADTokenExchange')
    description = 'flyw8t release environment only'
} | ConvertTo-Json -Compress
$ficFile = New-TemporaryFile
Set-Content -Path $ficFile -Value $fic -Encoding utf8
az ad app federated-credential create --id $appId --parameters "@$ficFile" --query subject -o tsv
Remove-Item $ficFile

# A new service principal can take a few seconds to become visible to role assignment.
Start-Sleep -Seconds 20
az role assignment create --assignee-object-id $spId --assignee-principal-type ServicePrincipal `
    --role 'Artifact Signing Certificate Profile Signer' --scope $profileScope --query roleDefinitionName -o tsv

gh secret set AZURE_CLIENT_ID --env release -R $repo --body $appId
Write-Host "Done. Now run: gh workflow run signing-check.yml -R $repo"
