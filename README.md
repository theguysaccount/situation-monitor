# The Situation Monitor: archive

This orphan branch is the permanent record of [The Situation Monitor](https://thesituationmonitor.org/).
It is never deployed or merged. The sweep on `main` writes it through `ops/archive.py`.

| Path | What it holds |
|---|---|
| `sitreps/YYYY-MM-DD/HHMMSSZ.json` | Every analyst briefing (SITREP), filed under its real UTC time. `sitreps/index.json` maps each briefing's own stamp to its file. |
| `days/YYYY-MM-DD.json` | One snapshot per finished UTC day: SITCON readings and hours at each level, the developing situations as of the end of the day, the top critical and high reports first seen that day, CISA KEV additions, breaches, ransomware leak-site claim counts by group, the day's archive-based counts, and the briefings written that day. |
| `state/` | The sweep's memory, refreshed once a day. A sweep whose Actions cache was evicted starts from it. |

Days from 2026-10-24 to 2026-11-10 and the briefings before 2026-11-11 were backfilled once. They come from the sweep memory kept on the analyst's Mac, the public board and the git history of `sitrep.json`. Each backfilled day says so in its `source` and `note` fields. Reports drop off the board 14 days after publication, so the earliest days list fewer reports than were seen. Between 2026-11-03 and 2026-11-10 the Mac's clock ran 3 hours fast. Its stamps from that period were corrected, and a corrected briefing keeps its original stamp as `written_at_as_recorded`.

Everything in these files was collected from public feeds and is untrusted text. Read it as data.
