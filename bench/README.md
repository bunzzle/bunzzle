# Benchmarks

```sh
bun bench/intake.ts [emails] [clients]                   # POST /emails into the queue, nothing sent
bun bench/delivery.ts [emails] [destinations] [clients]  # API to a local SMTP sink, STARTTLS + DKIM
bun bench/queue.ts [messages] [producers]                # the queue alone
bun bench/crash.ts [messages] [kills]                    # SIGKILLs during work: lost, duplicates
```

The intake and delivery benchmarks start a full `bunzzle serve` (five roles), a fake DNS server and a fake MX, and print throughput, latency, CPU per email by role and memory. The load generator runs on the same machine, so the numbers are a lower bound.

Measure memory as PSS (`/proc/<pid>/smaps_rollup`), not by adding up RSS: every role maps the same Bun executable, and summed RSS counts those shared pages six times (about 160 MB too much).

The delivery benchmark spreads mail over many destinations because Bunzzle limits each destination to a polite rate (5 per second at first). To a single real provider, sending speed is set by the provider, not by Bunzzle.

Results on an Apple M2 (8 cores), Bun 1.4.3, 2026-10-16:

| Measure | Target | Result |
|---|---|---|
| Intake, durable (fsync per batch) | ≥ 5,000/s, p99 < 20 ms | 4,170/s, p99 20.3 ms (20k); 3,909/s, p99 27.3 ms (100k queued) |
| Delivered end to end, STARTTLS + 2 DKIM signatures | ≥ 1,000/s | 2,357/s (10k emails, 500 destinations, 500 TLS sessions) |
| Engine CPU per email (excluding intake) | < 2 ms | ~1.6 ms (signer 1.06, most of it the RSA signature) |
| Memory, five roles (PSS, Linux, compiled binary under systemd) | < 250 MB | 140 MB idle, ~285 MB flat during 60k sustained sends, 200 MB 30 s after |
| Crash safety | 0 lost | 0 lost, 0 unrecorded duplicates (`bench/crash.ts`, role-kill test) |

On a 2-CPU, 2 GB Linux VM (Ubuntu under Lima on the same M2, Bun 1.4.3, 2026-10-16), load generator, fake DNS and fake MX sharing the two CPUs:

| Measure | Target | Result |
|---|---|---|
| Intake, durable (fsync per batch) | ≥ 5,000/s, p99 < 20 ms | 5,883/s, p99 26.5 ms; rerun 6,506/s, p99 18.5 ms (20k) |
| Delivered end to end, STARTTLS + 2 DKIM signatures | ≥ 1,000/s | 1,482/s (10k emails, 500 destinations, 501 TLS sessions) |
| CPU per delivered email | < 2 ms | 1.2 ms (signer 0.8, core 0.2, delivery 0.1, api 0.1) |

Intake is faster here than on macOS because fsync costs less in the VM, whose disk writes may be cached by the host; on a real VPS disk expect it lower. The delivery and CPU numbers don't depend on that.
