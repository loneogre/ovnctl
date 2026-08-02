"""
ovnctl subcommands -- one module per script in the original shell suite.

    bash                          python
    ------------------------      ----------------------------------
    ovn-setup.sh                  ovnctl setup
    ovn-localnet-internal.sh      ovnctl localnet-internal
    ovn-localnet-external.sh      ovnctl localnet-external
    ovn-vm-config.sh              ovnctl vm-config
    ovn-vm-isolation.sh           ovnctl vm-isolation
    ovn-acl.sh                    ovnctl acl
    ovn-vm-attach.sh              ovnctl vm-attach
    ovn-pcap.sh                   ovnctl pcap
    ovn-diagnose.sh               ovnctl diagnose
    ovndelete.sh                  ovnctl delete   (alias: teardown)
    tools/ovn-show                ovnctl show
    ovn-deploy.sh                 ovnctl deploy
    ovn-runbook.sh                ovnctl runbook

MODULES is the registration order, which is also the order subcommands
appear in ``ovnctl --help``. Every module exposes the same three names:

    NAME        the subcommand as typed
    HELP        one-line summary for the help listing
    register()  attach a parser to the subparsers object; sets func=main
    main(ctx, args) -> int
"""

MODULES = (
    "deploy",
    "setup",
    "localnet_internal",
    "localnet_external",
    "vm_config",
    "vm_isolation",
    "acl",
    "vm_attach",
    "pcap",
    "reconcile",
    "user_vm",
    "diagnose",
    "show",
    "runbook",
    "delete",
)

__all__ = ["MODULES"]
