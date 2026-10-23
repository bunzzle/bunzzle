export async function onThisMachine(ip: string): Promise<boolean> {
  try {
    const socket = await Bun.udpSocket({ hostname: ip, port: 0 });
    socket.close();
    return true;
  } catch {
    return false;
  }
}
