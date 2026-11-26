# Host observations in Overview

The Host status chart counts authenticated, usable replies from the current
Overview load. It uses the registered fleet as its scale. Connections use Unix
peer identity or pinned mutual TLS.

The controller saves the latest usable observation for each registered host.
Each host row shows the time of a current reply or labels the saved state as a
previous observation. The browser displays UTC instants in the viewer's local
time with an explicit timezone indication. A failed authentication or an
unavailable result leaves the saved observation intact. Unregistering a host
removes its observation. Status requests use the existing Overview and host
review flows.

- **Baseline matches** means the agent reported a match with its protected
  baseline receipt. The controller’s latest saved revision can differ.
- **Drift detected** means the agent reported observed drift.
- **Missing baseline receipt** means the agent lacks a bound receipt.
- **Change in progress** means the status summary reports an active operation.
  Open the host’s review and apply page to inspect its phase.

The card lists unavailable, unqueried and unknown entries as gaps. An unavailable
status means the request could not establish the state. Unqueried means the
controller made no status request. Unknown covers a missing, ambiguous or
unrecognized summary. Those hosts still contribute to the registered fleet size.
When every entry is a gap, the card explains the missing classifications and
omits the bars. An empty registration list shows the first-use host guidance.

Desired revisions and controller observations live in the controller database.
The agent's protected receipts and local rollback journal remain the authority
for observed kernel ownership and rollback decisions.

Unit and integration tests cover late arrivals, failure handling, host deletion,
and UTC persistence. The single-mapping namespace fixture uses a real pinned
mutual TLS agent, then stops the listener and restarts the controller to verify
that Overview shows a coverage gap alongside the previous observation.
The database fixtures verify that the stored observation survives native backup
and restore on all five engines.
