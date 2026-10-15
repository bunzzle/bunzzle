# Benchmarks

```sh
bun bench/intake.ts [emails] [clients]                   # POST /emails into the queue, nothing sent
bun bench/delivery.ts [emails] [destinations] [clients]  # API to a local SMTP sink, STARTTLS + DKIM
bun bench/queue.ts [messages] [producers]                # the queue alone
bun bench/crash.ts [messages] [kills]                    # SIGKILLs during work: lost, duplicates
```

The intake and delivery benchmarks start a full `bunzzle serve` (five roles), a fake DNS server and a fake MX, and print throughput, latency, CPU per email by role and memory. The load generator runs on the same machine, so the numbers are a lower bound.

The delivery benchmark spreads mail over many destinations because Bunzzle limits each destination to a polite rate (5 per second at first). To a single real provider, sending speed is set by the provider, not by Bunzzle.

Results on an Apple M2 (8 cores), Bun 1.4.3, 2026-10-16:

| Measure | Target | Result |
|---|---|---|
| Intake, durable (fsync per batch) | ≥ 5,000/s, p99 < 20 ms | 4,170/s, p99 20.3 ms (20k); 3,909/s, p99 27.3 ms (100k queued) |
| Delivered end to end, STARTTLS + 2 DKIM signatures | ≥ 1,000/s | 2,357/s (10k emails, 500 destinations, 500 TLS sessions) |
| Engine CPU per email (excluding intake) | < 2 ms | ~1.6 ms (signer 1.06, most of it the RSA signature) |
| Memory, five roles + supervisor | < 250 MB | 214 MB with 100k queued; 505 MB right after a 10k delivery burst |
| Crash safety | 0 lost | 0 lost, 0 unrecorded duplicates (`bench/crash.ts`, role-kill test) |
