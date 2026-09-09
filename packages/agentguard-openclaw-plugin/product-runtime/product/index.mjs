// Node 24 native require keeps the same production ESM instance for the Host
// loader and public startup factory; no global bridge or alternate plugin path.
import { createRequire } from "node:module";
const { createOpenClawProductPlugin } = createRequire(import.meta.url)(
  "../../dist/runtime/product-composition.js",
);
export default createOpenClawProductPlugin();
