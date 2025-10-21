// Aggregates the Rollup-prebundled Stacks Connect build for browser consumption.
// Re-export everything so existing imports remain unchanged and provide a
// namespace default for backwards compatibility with earlier SDK versions.
import * as stacksConnect from './stacks-connect.bundle.js';

export * from './stacks-connect.bundle.js';
export default stacksConnect;
