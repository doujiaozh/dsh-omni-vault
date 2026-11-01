/**
 * Omni-Vault demo — the ORIGINAL local billing module.
 *
 * This is what the program looked like BEFORE extraction. It contains the
 * full billing logic and the full string table. After extraction, everything
 * marked below is gone from the local program: computeInvoice survives only
 * as 140 bytes of wasm bytecode in the cloud, and renderInvoice only as a
 * cloud-side module.
 */

/** Non-core helper — this one stays behind in the local (hollowed) copy. */
export function tierName(tier: number): string {
  return ["Starter", "Business", "Enterprise", "Unlimited"][tier] ?? "Unknown";
}

/** Non-core helper — stays local. */
export function formatCents(cents: number): string {
  return (cents / 100).toFixed(2);
}

/**
 * @vault Renders a full invoice — lifted to the cloud in full.
 * The strings it uses (company, bank account, seal) are marked secrets:
 * they are served by the cloud string table and never ship locally.
 */
export function renderInvoice(
  amountCents: number,
  units: number,
  tierIdx: number,
  months: number,
  lang: "zh" | "en",
): string {
  const COMPANY = /* @vault-str */ "Omni-Vault 演示科技有限公司";
  const BANK = /* @vault-str */ "招商银行 6225-8866-0421-7f3a";
  const SEAL = /* @vault-str */ "【电子公章】OMNI-VAULT-DEMO-7F3A9C";

  // self-contained on purpose: the cloud copy may not reference local helpers
  const TIER = ["Starter", "Business", "Enterprise", "Unlimited"];
  const fmt = (cents: number) => (cents / 100).toFixed(2);
  const tier = TIER[tierIdx] ?? "Unknown";

  const unitPrice = (tierIdx + 1) * 170;
  const gross = units * unitPrice;
  const discount = gross - amountCents;
  const dpct = gross > 0 ? ((discount / gross) * 100).toFixed(1) : "0.0";
  const periodZh = months >= 12 ? `${months} 个月（年付）` : `${months} 个月`;
  const periodEn = months >= 12 ? `${months} months (annual)` : `${months} months`;

  const zh = [
    `账单 — ${COMPANY}`,
    `套餐：${tier} × ${units} 单元 × ${periodZh}`,
    `原价：¥${fmt(gross)}（单价 ¥${fmt(unitPrice)}/单元）`,
    `折扣：-¥${fmt(discount)}（${dpct}%）`,
    `应付：¥${fmt(amountCents)}`,
    `收款账户：${BANK}`,
    `${SEAL}`,
  ];
  const en = [
    `INVOICE — ${COMPANY}`,
    `Plan: ${tier} × ${units} units × ${periodEn}`,
    `Subtotal: ¥${fmt(gross)} (¥${fmt(unitPrice)}/unit)`,
    `Discount: -¥${fmt(discount)} (${dpct}%)`,
    `Due: ¥${fmt(amountCents)}`,
    `Beneficiary: ${BANK}`,
    `${SEAL}`,
  ];
  return (lang === "en" ? en : zh).join("\n");
}
