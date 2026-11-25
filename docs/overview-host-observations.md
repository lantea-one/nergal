# Host observations in Overview

The Host status card summarizes the authenticated status requests already made
when Overview loads. The configured fleet connection uses Unix peer identity or
pinned mutual TLS. Each bar counts registered hosts with a usable classification
in that page load. All bars use the full registered fleet as their common scale.
The values are host counts for one page load and carry no packet, byte, throughput
or historical measurements.

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

The chart is a read-only projection of the existing Overview results. It adds no
requests, sampling schedule, observation storage or agent protocol changes.

The DashboardHostObservations unit tests cover mixed fleets, no registrations,
and unavailable, unqueried, unknown and ambiguous inputs. The appliance
navigation HTTPS fixture covers the first-use and unavailable states. The
single-mapping namespace check in the [test guide](testing.md#m5-console-acceptance)
uses a real agent and pinned mutual TLS to verify a populated bar and the
coverage gap that appears when the agent becomes unavailable.
