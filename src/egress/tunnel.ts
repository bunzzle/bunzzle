import type { Socket } from "bun";
import { Outbox, openStream, type TcpEndpoint } from "../ipc/rpc.ts";

export interface Via {
  name: string;
  open(host: string, port: number, source: string, timeoutMs: number): Promise<string>;
}

export function egressVia(name: string, endpoint: TcpEndpoint, dir: string): Via {
  return {
    name,
    async open(host, port, source, timeoutMs) {
      const stream = await openStream(endpoint, { host, port, source }, timeoutMs);
      const path = `${dir}/egress-${crypto.randomUUID()}.sock`;
      const remove = () =>
        Bun.file(path)
          .delete()
          .catch(() => {});
      let local: Socket<undefined> | null = null;
      let out: Outbox | null = null;
      const listener = Bun.listen({
        unix: path,
        socket: {
          open(s) {
            if (local) {
              s.end();
              return;
            }
            local = s;
            clearTimeout(timer);
            listener.stop();
            void remove();
            const toLocal = new Outbox(s);
            out = toLocal;
            stream.read(
              (chunk) => toLocal.write(chunk.slice()),
              () => s.end(),
            );
          },
          data(_s, chunk) {
            stream.write(chunk.slice());
          },
          drain() {
            out?.flush();
          },
          close() {
            stream.end();
          },
          error() {
            stream.end();
          },
        },
      });
      const timer = setTimeout(() => {
        if (local) return;
        listener.stop();
        stream.end();
        void remove();
      }, timeoutMs);
      await Bun.$`chmod 600 ${path}`.quiet();
      return path;
    },
  };
}
