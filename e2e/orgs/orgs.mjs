// One enterprise, one bae6 organization (tenant) per department.
export const ORGS = [
  "finance",
  "software",
  "executives",
  "legal",
  "hr",
  "sales",
  "marketing",
  "support",
  "security",
  "data",
  "operations",
  "procurement",
  "research",
  "product",
  "design",
  "it",
  "facilities",
  "compliance",
  "partnerships",
  "treasury",
].map((d) => `acme-${d}`);

export const orgIssuer = (base, org) => `${base}/orgs/${org}`;
