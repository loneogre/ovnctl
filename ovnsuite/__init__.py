"""
ovnsuite -- Python port of the OVN deployment/diagnostic shell suite.

Layout mirrors the original repository:

    <root>/configs/ovn-settings.yaml     central configuration
    <root>/configs/ovn-internal-ranges.conf   legacy fallback range list
    <root>/state/ovn-deploy-state        deployment tracker (mutable runtime data)

Every executable is a subcommand of ``ovnctl``. Each subcommand is further
divided into named steps so a single part of a deployment can be re-run
without executing the whole thing:

    ovnctl setup --list-steps
    ovnctl setup --only host-interface
    ovnctl localnet-internal --from transit-switch
"""

__version__ = "2.0.0"

__all__ = ["__version__"]
