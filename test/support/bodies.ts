import { type BodyFiles, BodyStoreError, type StoredBody } from "../../src/core/store/bodies.ts";

export function memoryBodies(): BodyFiles & { files: Map<string, StoredBody> } {
  const files = new Map<string, StoredBody>();
  return {
    files,
    async write(id, b, o) {
      if (files.has(id) && !o?.replace) throw new BodyStoreError(`${id} exists`, 17);
      files.set(id, b);
      return 10 + b.wrapped.length + b.body.length;
    },
    async read(id, epoch) {
      return files.get(id) ?? { epoch, wrapped: new Uint8Array(1), body: new Uint8Array(1) };
    },
    async remove(list) {
      let n = 0;
      for (const { id } of list) if (files.delete(id)) n++;
      return n;
    },
  };
}
