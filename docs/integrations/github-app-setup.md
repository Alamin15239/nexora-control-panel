# Configure the Nexora GitHub App

Nexora uses two separate GitHub steps:

1. OAuth authorization links a GitHub identity to a Nexora organization.
2. GitHub App installation grants the Nexora App repository-scoped access on a personal account or organization.

Completing OAuth alone does not install the GitHub App and must not be treated as repository access.

## GitHub App settings

In GitHub, open **Settings → Developer settings → GitHub Apps → Nexora** and configure:

- **Setup URL:** `https://api.nexoraedge.digital/v1/github/installation-callback`
- **User authorization callback URL:** keep the existing configured OAuth callback, `https://api.nexoraedge.digital/v1/github/callback`.
- **Repository permissions:**
  - Metadata: Read-only (required by GitHub).
  - Contents: Read-only.
  - Actions: Read and write (used by the deployment workflow integration).
- **Webhook:** set the URL to `https://api.nexoraedge.digital/v1/github/webhooks`, configure a strong webhook secret, and subscribe to **Push** and **Pull requests** events. Store the exact same secret in the Nexora API Worker as `GITHUB_APP_WEBHOOK_SECRET`. This is one App-level webhook for all repositories covered by the installation; per-repository webhook setup is not required.
- **Where can this GitHub App be installed?** Choose the intended availability (any account, or only the Nexora-controlled organization).

The API verifies the installation ID against the configured GitHub App ID using an App JWT before binding it to the Nexora organization. The callback state is random, hashed at rest, expires after 15 minutes, and can be consumed only once.

## Customer installation flow

1. In Nexora Deploy, select **Connect GitHub** and complete OAuth authorization if not already connected.
2. Select **Install Nexora GitHub App**.
3. In GitHub, choose the personal account or organization and select **All repositories** or **Only select repositories**. For the latter, select at least one repository.
4. Return to Nexora Deploy. The verified installation should be shown and the repository list should load.
5. Link a repository to its hosting account. Production auto-deploy is enabled by default: pushes to the selected production branch trigger a deployment. You can explicitly turn it off in Deploy settings.

Repository discovery uses the GitHub App installation API, not the OAuth user's installation list. Project linking re-verifies the selected repository using a short-lived installation token scoped to that repository. The App-level webhook authenticates events with its shared secret and matches the repository and installation IDs to the linked project.

## Disconnect behavior

Disconnecting in Nexora revokes the OAuth grant where possible and removes Nexora's local connection and project links. It does not uninstall the GitHub App from the GitHub account; uninstall it separately in GitHub **Settings → Applications → Installed GitHub Apps** if you also want to remove the account-level installation.
