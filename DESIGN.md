# ShardGuard Design System

Product craft for the public landing page and offline triage report.
Tone: infrastructure security tool — high contrast, restrained accent, sharp type.

## Brand

- **Name:** ShardGuard
- **Promise:** Find malicious logic fragmented across files and hidden behind encoding / unicode tricks.
- **Voice:** Precise, calm, honest about limits. No hype.

## Color

| Token | Value | Use |
|-------|-------|-----|
| `--bg` | `#0c0d0f` | Page background |
| `--surface` | `#14161a` | Panels |
| `--border` | `#2a2e36` | Rules / dividers |
| `--text` | `#e8eaed` | Primary text |
| `--muted` | `#8b919a` | Secondary text |
| `--accent` | `#d97706` | Single accent (amber / oxide) — CTAs, P0 dots |
| `--crit` | `#ef4444` | Critical |
| `--high` | `#f97316` | High |
| `--med` | `#eab308` | Medium |
| `--low` | `#64748b` | Low / info |
| `--ok` | `#22c55e` | Clean / pass |

Never use purple gradients, neon glow stacks, or multi-accent rainbow chips.

## Typography

- UI: `"IBM Plex Sans", "Segoe UI", system-ui, sans-serif`
- Mono: `"IBM Plex Mono", ui-monospace, Consolas, monospace`
- Landing may load Plex from Google Fonts; **offline report uses system stack only**.
- Scale: 12 / 14 / 16 / 20 / 28 / 40 (line-height 1.4 body, 1.1 display)

## Spacing & radius

- 4px grid: 8, 12, 16, 24, 40, 64
- Radius: 4–6px (sharp, not pill)

## Motion

- Duration: 120ms (micro), 220ms (panel)
- Easing: `cubic-bezier(0.2, 0.8, 0.2, 1)`
- Respect `prefers-reduced-motion: reduce`
- Allowed: copy flash, filter chip transition, finding expand

## Microstates

Every control: default, hover, focus-visible (2px accent outline), active, disabled.

## Layout

- Landing: one composition first viewport — brand hero, one headline, one sentence, one CTA.
- Report: app shell — topbar, file tree, finding list, detail pane.

## Anti-patterns

- Purple-on-white / indigo glow themes
- Cream + terracotta serif “editorial” look
- Broadsheet dense columns
- Emoji icon rows, floating promo badges on hero
- Card soup in the first viewport
