# Changelog

## v0.4.0 - Runtime Policy Autonomy

Release prep for the next minor line after `v0.3.3`.

### Added

- Natural Intent to Forge to `RuntimePolicyPack` integration coverage for the
  KLShield runtime path.
- Forge support-report workflow in the manual runbook, so policy writers can see
  enforced, carried, warning and unsupported intent features before activation.
- Runtime policy autonomy fields for enforcement-feedback holds, previous-action
  requirements, risk confidence and freshness, independent-signal requirements,
  max action duration and audit receipt requirements.
- Broker and resolver gates for simple hard autonomy constraints.
- KLIQ runtime logs and metrics for pass/drop rates, including KLShield
  rate-limit feedback.
- Standalone manual commands for replaying
  `tests/integration/fixtures/policies/klshield-edge-autonomy-hold.intent`
  through Forge and loading the generated pack in KLIQ.

### Changed

- Active RuntimePDP is documented as the enforcement authority; adapter analyzers
  and FSM paths provide facts and proposals.
- KLShield source rate limiting is documented as an approximate pass budget:
  `rate_pps=100` means about 100 packets per second pass, while `drop_rl_rate`
  reports packets rejected above that budget.
- Scenario 12 now starts from productive Natural Intent and validates the full
  conversion path before KLIQ loads the generated `RuntimePolicyPack`.
- Installer next-step output now points at explicit whitelist, feedback, state
  and SQLite paths for repeatable runs.

### Fixed

- KLShield source rate-limit state is protected against concurrent token-bucket
  updates in the XDP path.
- RuntimePDP signal-window application now projects active source leases before
  applying stronger actions, avoiding misleading state transitions.
- KLShield PEP map update/delete errors are surfaced instead of being silently
  ignored.

### Notes

- The Kernloom release line can move to `v0.4.0` while the imported
  `github.com/kernloom/kernloom-contracts` wire schemas remain at their own
  `v0.3.0` module version.
- KLIQ still does not load `.intent` files directly. Natural Intent remains
  Forge input; KLIQ loads the generated `RuntimePolicyPack` or a signed
  `RuntimeBundle`.
