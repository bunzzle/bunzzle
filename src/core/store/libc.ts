import { dlopen, FFIType, read, suffix } from "bun:ffi";

const MAC = suffix === "dylib";

export const EEXIST = 17;
export const EINTR = 4;
export const ENOENT = 2;

const CREATE_NEW = MAC ? 0x1 | 0x200 | 0x800 | 0x1000000 : 0x1 | 0x40 | 0x80 | 0x80000;

export class Errno extends Error {
  constructor(
    message: string,
    readonly errno: number,
  ) {
    super(message);
  }
}

export function openLibc() {
  const { symbols } = dlopen(MAC ? "/usr/lib/libSystem.B.dylib" : "libc.so.6", {
    creat: { args: [FFIType.cstring, FFIType.u32], returns: FFIType.i32 },
    open: { args: [FFIType.cstring, FFIType.i32], returns: FFIType.i32 },
    fchmod: { args: [FFIType.i32, FFIType.u32], returns: FFIType.i32 },
    write: { args: [FFIType.i32, FFIType.ptr, FFIType.u64], returns: FFIType.i64_fast },
    fsync: { args: [FFIType.i32], returns: FFIType.i32 },
    fdatasync: { args: [FFIType.i32], returns: FFIType.i32 },
    close: { args: [FFIType.i32], returns: FFIType.i32 },
    mkdir: { args: [FFIType.cstring, FFIType.u32], returns: FFIType.i32 },
    unlink: { args: [FFIType.cstring], returns: FFIType.i32 },
    [MAC ? "__error" : "__errno_location"]: { args: [], returns: FFIType.ptr },
  });
  const errnoAt = symbols[MAC ? "__error" : "__errno_location"] as () => number | null;
  const enc = new TextEncoder();
  const c = (path: string) => enc.encode(`${path}\0`);
  const errno = () => {
    const p = errnoAt();
    return p === null ? -1 : read.i32(p, 0);
  };
  const fail = (what: string, path: string) => {
    const n = errno();
    return new Errno(`body store: ${what} ${path} failed (errno ${n})`, n);
  };
  const retry = (call: () => number) => {
    for (;;) {
      const r = call();
      if (r >= 0 || errno() !== EINTR) return r;
    }
  };

  return {
    create(path: string, mode: number): number {
      const fd = retry(() => symbols.creat(c(path), mode));
      if (fd < 0) throw fail("create", path);
      return fd;
    },
    createNew(path: string, mode: number): number {
      const fd = retry(() => symbols.open(c(path), CREATE_NEW));
      if (fd < 0) throw fail("create", path);
      if (retry(() => symbols.fchmod(fd, mode)) !== 0) {
        const err = fail("chmod", path);
        symbols.close(fd);
        symbols.unlink(c(path));
        throw err;
      }
      return fd;
    },
    openRead(path: string): number {
      const fd = retry(() => symbols.open(c(path), 0));
      if (fd < 0) throw fail("open", path);
      return fd;
    },
    writeAll(fd: number, data: Uint8Array, path: string): void {
      let off = 0;
      while (off < data.length) {
        const part = data.subarray(off);
        const n = retry(() => Number(symbols.write(fd, part, part.length)));
        if (n <= 0) throw fail("write", path);
        off += n;
      }
    },
    syncData(fd: number, path: string): void {
      if (retry(() => (MAC ? symbols.fsync(fd) : symbols.fdatasync(fd))) !== 0)
        throw fail("sync", path);
    },
    sync(fd: number, path: string): void {
      if (retry(() => symbols.fsync(fd)) !== 0) throw fail("sync", path);
    },
    close(fd: number): void {
      symbols.close(fd);
    },
    mkdir(path: string, mode: number): boolean {
      if (retry(() => symbols.mkdir(c(path), mode)) === 0) return true;
      if (errno() === EEXIST) return false;
      throw fail("mkdir", path);
    },
    unlink(path: string): boolean {
      if (retry(() => symbols.unlink(c(path))) === 0) return true;
      if (errno() === ENOENT) return false;
      throw fail("unlink", path);
    },
  };
}

export type Libc = ReturnType<typeof openLibc>;
