# Cloudflare API Preview Build

The API Worker package is `@nexora/cloudflare-api` in the pnpm workspace.

Configure the Cloudflare Preview environment with:

- Root directory: `/`
- Build command: `pnpm --filter @nexora/cloudflare-api build`
- Preview command: `pnpm --filter @nexora/cloudflare-api preview`

Run both commands from the repository root. The pnpm workspace filter executes each package script in `apps/cloudflare-api`, where `wrangler.toml` is located.

Do not use `npx wrangler preview` from the repository root, and do not use the unscoped package filter `nexora-cloudflare-api`.

The Preview command is for validation only. Production deployment remains a separate, explicitly approved operation.
