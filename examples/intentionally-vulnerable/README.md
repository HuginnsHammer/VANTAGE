# Intentionally vulnerable training workspace

This directory is a disposable, deliberately insecure fixture for local scanner development.
It is not a production template. Do not deploy it or copy its settings into real workloads.

Expected learning themes include privileged containers, exposed management sockets, broad
network exposure, and permissive infrastructure defaults. Scanner coverage depends on the
CloudSentry rules installed in the local environment; this fixture is not a claim that every
issue is currently detected.
