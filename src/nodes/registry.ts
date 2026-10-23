import type { Database } from "bun:sqlite";

export interface DeliveryNode {
  name: string;
  address: string;
  pin: string;
  notAfter: number;
  createdAt: number;
}

interface Row {
  name: string;
  address: string;
  pin: string;
  not_after: number;
  created_at: number;
}

const fromRow = (r: Row): DeliveryNode => ({
  name: r.name,
  address: r.address,
  pin: r.pin,
  notAfter: r.not_after,
  createdAt: r.created_at,
});

export function addNode(db: Database, n: DeliveryNode): boolean {
  return (
    db
      .query<unknown, [string, string, string, number, number]>(
        `INSERT INTO nodes (name, address, pin, not_after, created_at) VALUES (?, ?, ?, ?, ?)
         ON CONFLICT DO NOTHING`,
      )
      .run(n.name, n.address, n.pin, n.notAfter, n.createdAt).changes > 0
  );
}

export function listNodes(db: Database): DeliveryNode[] {
  return db.query<Row, []>("SELECT * FROM nodes ORDER BY name").all().map(fromRow);
}

export function getNode(db: Database, name: string): DeliveryNode | null {
  const r = db.query<Row, [string]>("SELECT * FROM nodes WHERE name = ?").get(name);
  return r ? fromRow(r) : null;
}

export function renewNode(db: Database, name: string, pin: string, notAfter: number): boolean {
  return (
    db
      .query<unknown, [string, number, string]>(
        "UPDATE nodes SET pin = ?, not_after = ? WHERE name = ?",
      )
      .run(pin, notAfter, name).changes > 0
  );
}

export function removeNode(db: Database, name: string): boolean {
  return db.query<unknown, [string]>("DELETE FROM nodes WHERE name = ?").run(name).changes > 0;
}
