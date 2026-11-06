# Run the hosted VANTAGE workspace locally

This development stack starts four components:

- PostgreSQL 16 for tenant data.
- Keycloak 26.8.2 as a local OIDC identity provider.
- A one-shot migration/provisioning container that creates the schema and a
  restricted non-owner runtime database role.
- The hosted VANTAGE API and browser workspace on port 8765.

It is deliberately a development environment. It uses HTTP on localhost,
Keycloak's development mode and a PostgreSQL superuser only in the one-shot
migration container. Never expose these services to the public internet or
reuse these settings in production.

## Requirements

- Docker Engine
- Docker Compose v2
- 4 GB or more free memory recommended for PostgreSQL, Keycloak and VANTAGE
- Ports 5432, 8080 and 8765 available

## Configure local secrets

From the VANTAGE repository root:

~~~fish
cp .env.dev.example .env.dev
openssl rand -hex 24
~~~

Generate three separate random values and place them in .env.dev:

- POSTGRES_PASSWORD
- KEYCLOAK_ADMIN_PASSWORD
- VANTAGE_RUNTIME_DB_PASSWORD

Do not commit .env.dev. It is ignored by Git. The committed example contains
placeholders only.

## Start the stack

~~~fish
docker compose --env-file .env.dev -f docker-compose.dev.yml up --build
~~~

The migration service runs Alembic and provisions vantage_app with
NOSUPERUSER, NOBYPASSRLS and no ownership of tenant tables. The API uses only
that restricted runtime role. Keycloak imports the vantage-dev realm and
vantage-web public client with Authorization Code + PKCE (S256).

Wait until the API container is running, then open:

- Hosted VANTAGE workspace: http://localhost:8765/app
- API documentation: http://localhost:8765/api/docs
- Keycloak administration: http://localhost:8080/admin

Use the Keycloak admin username/password from .env.dev for the admin console.
On the VANTAGE sign-in page, continue to Keycloak and use its local account
registration link to create a development user. No real email delivery is
configured in this local realm.

## Try the workspace

1. Sign in. VANTAGE provisions your personal workspace automatically.
2. Create an organization workspace and switch between it and your personal
   workspace.
3. Create a project.
4. Register a public domain that you own or are explicitly authorized to manage.
5. Request a DNS TXT challenge and publish the exact record in that domain's
   DNS provider.
6. Return to VANTAGE and verify the challenge after DNS propagation.

A successful DNS proof establishes control of the domain namespace only. It
does not authorize active testing. Hosted scanners are not connected yet.

## Useful commands

~~~fish
docker compose --env-file .env.dev -f docker-compose.dev.yml ps
docker compose --env-file .env.dev -f docker-compose.dev.yml logs -f api keycloak
docker compose --env-file .env.dev -f docker-compose.dev.yml down
~~~

The named volumes preserve PostgreSQL and Keycloak development data. To erase
all local accounts and workspace data, run:

~~~fish
docker compose --env-file .env.dev -f docker-compose.dev.yml down -v
~~~

## Troubleshooting

- If ports are occupied, stop the conflicting services before starting VANTAGE.
  If you change the API or Keycloak host ports, also update the redirect URI,
  issuer and Keycloak realm redirect/web-origin values consistently.
- If Keycloak is still starting, wait a little and reload the sign-in page.
- If API startup fails, inspect the migration and API logs. The API deliberately
  refuses a database superuser, BYPASSRLS role or tenant-table owner.
- If the browser reports a token audience error, inspect the imported
  vantage-api client scope and its audience mapper in the Keycloak admin UI.
- DNS TXT verification requires a real public domain and a resolvable TXT
  record. The automated tests mock DNS and do not contact real domains.
