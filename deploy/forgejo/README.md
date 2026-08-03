# Forgejo archive target

Forgejo is the durable private archive remote, not a live database. Only the
single logical exporter may push. Production deployment should place the remote
outside the canonical Memory Node failure domain.
