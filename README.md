# VR GATEKEEPER

**The Spatial Decision Firewall** — Meta VR Start Developer Competition 2026, Productivity track.

A hands-first WebXR experience: run preset queries through a Headroom admission-control gate visualized in 3D space, entirely through hand gestures (no controllers). Admitted queries bloom into green verdict panels. Refused queries — jailbreaks, prompt injections — visibly shatter into red fragments with the refusal reason displayed.

## Hands-first interaction
- **Pinch** to grab an orb, release to send it through the gate
- **Grab** to move panels
- **Palm-up** for menu (Reset / Ledger / Telemetry)

Fully usable end-to-end without controllers. The experience detects live controllers and missing hand tracking and warns before the test begins.

## Measured on Quest (2026-10-10)
- 21-verdict live session on Quest hardware: 10 admitted / 11 refused
- 90 FPS average, p95 frame time 11.9ms
- Hand-tracking session with controllers down; hand skeleton renders in-scene on scan-in
- Session telemetry panel: frame percentiles, per-verdict engine compute time, interaction counts

## Tech
- WebXR (immersive-vr) with native hand-tracking input
- Runs on Quest browser — no native SDK required
- Mouse/touch fallback for desktop preview
- Refusal engine: Headroom admission control, ported to dependency-free JavaScript (`headroom.js`) from the Python reference implementation. Grant iff claimed resources fit inside measured headroom AND residual is within epsilon. Patent-pending IP: 64/150,688.

## Honesty notes
- Demo visualization of the admission gate. The query→engine mapping is illustrative; the ledger is in-memory only.
- Not a production safety system, not a real AI assistant.

## Competition
Meta VR Start Developer Competition 2026 — Productivity track, New Experience division. Deadline: November 18, 2026, 12:00 PM PT.
Playable build: https://snowphamtom.github.io/vr-gatekeeper/

## License
MIT — see LICENSE. Patent notice: underlying admission-control technology is patent-pending (64/150,688); this license covers demo code only.
