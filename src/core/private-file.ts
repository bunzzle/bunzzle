export async function writePrivateJson(path: string, data: unknown): Promise<void> {
  const tmp = `${path}.${crypto.randomUUID()}.tmp`;
  await Bun.write(tmp, `${JSON.stringify(data, null, 2)}\n`);
  await Bun.$`chmod 600 ${tmp} && mv -f ${tmp} ${path}`.quiet();
}
