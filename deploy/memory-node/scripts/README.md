# Memory Node deployment scripts

The Milestone 1 foundation uses the explicit, reviewable install and verification
commands in `../systemd/README.md` and `../postgresql/README.md`. No unattended
installer is provided yet because existing-node database migration and storage
validation require operator decisions.

Future deployment and restore scripts will use fixed argument arrays, validated
paths, mount-point checks, and explicit service users. They must fail closed on
unexpected ownership or storage layout and must not embed credentials or private
network coordinates.
