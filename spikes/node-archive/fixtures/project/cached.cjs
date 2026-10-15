globalThis.probeCount = (globalThis.probeCount || 0) + 1;
module.exports = {count:globalThis.probeCount};
