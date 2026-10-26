# Benchmarks

```sh
bun bench/intake.ts [emails] [clients]
bun bench/delivery.ts [emails] [destinations] [clients]
bun bench/realistic.ts <case> [emails] [destinations] [clients]
bun bench/queue.ts [messages] [producers]
bun bench/crash.ts [messages] [kills]
bun bench/ns-slip.ts [seconds] [flood rates]
```

- `intake`: `POST /emails` into the queue, nothing sent.
- `delivery`: API to a local SMTP sink, with STARTTLS and DKIM.
- `realistic`: delivery with one case at a time: `base`, `medium` (50 KB html), `large` (50 KB html and a 100 KB attachment), `recipients` (5 per email), `webhooks`, `tracking`, `eventlog`, `all` (the five before together), `slow` (every receiver answers after `BENCH_SLOW_MS`, default 2,000 ms) and `backlog` (`BENCH_BACKLOG` emails, default 5,000,000, scheduled for the next day first). Prints delivered messages per second and CPU per message for each role.
- `queue`: the queue alone.
- `crash`: kills roles with SIGKILL during work and counts lost and duplicate emails.
- `ns-slip`: a spoofed UDP query flood against the `ns` rate limit, with limited answers dropped and with every second one sent as a truncated reply: bytes reflected to the spoofed address, and answers a real resolver in the same and in another network still gets.

The `Bench` workflow (Actions, started by hand) runs `realistic` on a Linux runner for the chosen cases and writes the output to the job summary. Shared runners are noisy: compare runs made close together.

The intake and delivery benchmarks start a full `bunzzle serve` (five roles), a fake DNS server and a fake MX, and print throughput, latency, CPU per email by role and memory. The load generator runs on the same machine, so the numbers are a lower bound.

Measure memory as PSS (`/proc/<pid>/smaps_rollup`), not by adding up RSS: every role maps the same Bun executable, and summed RSS counts those shared pages six times.

The delivery benchmark spreads mail over many destinations because Bunzzle limits each destination to a polite rate (5 per second at first). To a single real provider, sending speed is set by the provider, not by Bunzzle.
