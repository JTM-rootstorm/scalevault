# Memory Node units

The API and node-agent unit skeletons are checked in first. Worker, ingress,
exporter, and timer units will be added with their runnable entry points so the
deployment never advertises a service that only exits as unimplemented.
