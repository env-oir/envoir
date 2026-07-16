// bus.js — a tiny late-bound dispatch table so view modules and the shell don't import each
// other in a cycle. The shell fills these in at mount time; views just call bus.rerender().
export const bus = {
  setView: (_v) => {},     // switch primary view
  rerender: () => {},      // re-render the current view in place
  refreshChrome: () => {}, // update rail counts / topbar after data changes
};
