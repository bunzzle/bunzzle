export interface SmtpTalk {
  replies: string[];
  last: string;
}

export async function smtpTalk(port: number, commands: string[]): Promise<SmtpTalk> {
  const replies: string[] = [];
  let buffer = "";
  let wake: (() => void) | null = null;
  const socket = await Bun.connect({
    hostname: "127.0.0.1",
    port,
    socket: {
      data(_s, chunk) {
        buffer += new TextDecoder().decode(chunk);
        wake?.();
      },
    },
  });
  const nextReply = async () => {
    for (;;) {
      const lines = buffer.split("\r\n");
      for (let i = 0; i < lines.length - 1; i++) {
        if (/^\d{3} /.test(lines[i] as string)) {
          const reply = lines.slice(0, i + 1).join("\n");
          buffer = lines.slice(i + 1).join("\r\n");
          return reply;
        }
      }
      await new Promise<void>((r) => {
        wake = r;
        setTimeout(r, 5_000);
      });
    }
  };
  replies.push(await nextReply());
  for (const c of commands) {
    socket.write(`${c}\r\n`);
    replies.push(await nextReply());
  }
  socket.end();
  return { replies, last: replies.at(-1) ?? "" };
}

export function deliverMail(port: number, rcpt: string, message: string) {
  const body = message.replace(/\r?\n/g, "\r\n").replace(/^\./gm, "..");
  return smtpTalk(port, [
    "EHLO reporter.example.test",
    "MAIL FROM:<>",
    `RCPT TO:<${rcpt}>`,
    "DATA",
    `${body}\r\n.`,
    "QUIT",
  ]);
}
