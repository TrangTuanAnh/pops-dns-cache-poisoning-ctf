# registrar-service

Small HTTP stub for the lab registrar abstraction. It records requested domain
delegations in JSON but does not yet rewrite NSD zones or reload the server.

Useful endpoints:

- `GET /health`
- `GET /api/v1/registrations`
- `POST /api/v1/register` with `{"domain":"team1.example","ns_ip":"10.0.2.50"}`

