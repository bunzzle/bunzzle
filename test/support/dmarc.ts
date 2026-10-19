const enc = new TextEncoder();

export const REPORT = `<?xml version="1.0" encoding="UTF-8" ?>
<feedback xmlns="urn:ietf:params:xml:ns:dmarc-2.0">
  <report_metadata>
    <org_name>mail.example</org_name>
    <email>noreply-dmarc@mail.example</email>
    <report_id>17290000001234</report_id>
    <date_range><begin>1729296000</begin><end>1729382399</end></date_range>
  </report_metadata>
  <policy_published><domain>acme.test</domain><p>none</p><pct>100</pct></policy_published>
  <record>
    <row>
      <source_ip>203.0.113.5</source_ip>
      <count>42</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
    </row>
    <identifiers><header_from>acme.test</header_from><envelope_from>bounce.acme.test</envelope_from></identifiers>
    <auth_results>
      <dkim><domain>acme.test</domain><selector>bz1</selector><result>pass</result></dkim>
      <spf><domain>bounce.acme.test</domain><result>pass</result></spf>
    </auth_results>
  </record>
  <record>
    <row>
      <source_ip>198.51.100.7</source_ip>
      <count>3</count>
      <policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated>
    </row>
    <identifiers><header_from>ACME.test</header_from></identifiers>
    <auth_results><spf><domain>spoof.example</domain><result>fail</result></spf></auth_results>
  </record>
</feedback>`;

function u32(n: number) {
  return [n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >>> 24) & 0xff];
}
const u16 = (n: number) => [n & 0xff, (n >> 8) & 0xff];

export function zip(name: string, content: Uint8Array<ArrayBuffer>): Uint8Array {
  const data = Bun.deflateSync(content);
  const crc = Bun.hash.crc32(content);
  const n = enc.encode(name);
  const local = [
    ...u32(0x04034b50),
    ...u16(20),
    ...u16(0),
    ...u16(8),
    ...u16(0),
    ...u16(0),
    ...u32(crc),
    ...u32(data.length),
    ...u32(content.length),
    ...u16(n.length),
    ...u16(0),
  ];
  const central = [
    ...u32(0x02014b50),
    ...u16(20),
    ...u16(20),
    ...u16(0),
    ...u16(8),
    ...u16(0),
    ...u16(0),
    ...u32(crc),
    ...u32(data.length),
    ...u32(content.length),
    ...u16(n.length),
    ...u16(0),
    ...u16(0),
    ...u16(0),
    ...u16(0),
    ...u32(0),
    ...u32(0),
  ];
  const cdStart = local.length + n.length + data.length;
  const cdSize = central.length + n.length;
  const end = [
    ...u32(0x06054b50),
    ...u16(0),
    ...u16(0),
    ...u16(1),
    ...u16(1),
    ...u32(cdSize),
    ...u32(cdStart),
    ...u16(0),
  ];
  return Uint8Array.from([...local, ...n, ...data, ...central, ...n, ...end]);
}

export function reportMail(type: string, filename: string, content: Uint8Array): string {
  return [
    "From: noreply-dmarc@mail.example",
    "To: dmarc@bounce.acme.test",
    "Subject: Report Domain: acme.test",
    'Content-Type: multipart/mixed; boundary="R"',
    "",
    "--R",
    "Content-Type: text/plain",
    "",
    "This is a DMARC aggregate report.",
    "--R",
    `Content-Type: ${type}; name="${filename}"`,
    "Content-Transfer-Encoding: base64",
    `Content-Disposition: attachment; filename="${filename}"`,
    "",
    content.toBase64().replace(/.{76}/g, "$&\r\n"),
    "--R--",
    "",
  ].join("\r\n");
}

export function reportXml(domain = "acme.test", begin = 1729296000, id = "17290000001234"): string {
  return REPORT.replace("<domain>acme.test</domain>", `<domain>${domain}</domain>`)
    .replace("<begin>1729296000</begin>", `<begin>${begin}</begin>`)
    .replace("<end>1729382399</end>", `<end>${begin + 86_399}</end>`)
    .replace("17290000001234", id);
}
