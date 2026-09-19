// Register the test-only loader without the deprecated command-line flag on
// Node releases that expose module.register().
import { register } from "node:module";

register("./custodian-checkpoint-race-loader.mjs", import.meta.url);
