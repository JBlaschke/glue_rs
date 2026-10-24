import { readFileSync } from "node:fs";
import ms from "ms";

// Use a module-relative URL so the same resource works from another cwd and
// from glue's archive. `ms` is an installed npm dependency, not vendored code.
const tasks = JSON.parse(
  readFileSync(new URL("../data/tasks.json", import.meta.url), "utf8"),
);
const durations = tasks.map(({ duration }) => ms(duration));
if (durations.some((duration) => !Number.isFinite(duration) || duration <= 0)) {
  throw new Error("Every task must have a positive duration understood by ms");
}
const total = durations.reduce((sum, duration) => sum + duration, 0);

console.log(`tasks=${tasks.length}`);
console.log(`total=${ms(total, { long: true })}`);
console.log(`milliseconds=${total}`);
console.log(`argument=${process.argv[2] ?? "hello from node"}`);
