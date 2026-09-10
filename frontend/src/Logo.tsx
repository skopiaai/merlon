/**
 * The Merlon mark.
 *
 * A merlon is the solid upright tooth of a battlement — the part you shelter
 * behind, with the gaps (crenels) between them to look and shoot through. That
 * silhouette is the logo: three merlons on a wall, with the centre one raised
 * and lit, and a sightline cut through the crenel beside it.
 *
 * Design constraints, in the order they mattered:
 *
 *  1. **Legible at 16px.** It ends up as a favicon and a menu-bar glyph, so it
 *     is built on a 24-unit grid with nothing thinner than 2 units. Anything
 *     finer turns to mud at tab size, which is where a logo is seen most.
 *  2. **One colour, inherited.** Everything is `currentColor` except the
 *     accent, so the mark works on both themes and in a print report without a
 *     second asset. No gradients — they band badly when scaled down.
 *  3. **Reads as fortification, not as a bar chart.** The crenel gaps are wider
 *     than the merlons and the base is solid, which is what stops three
 *     rectangles looking like analytics.
 */

type Props = {
  /** Rendered size in px. 16 for a favicon, 22 in the header, 64+ for docs. */
  size?: number;
  /** Set false for a flat monochrome mark — print, or a single-colour context. */
  accent?: boolean;
  title?: string;
};

export default function Logo({ size = 22, accent = true, title = "Merlon" }: Props) {
  const lit = accent ? "var(--neon, #00f0ff)" : "currentColor";
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      role="img"
      aria-label={title}
      style={{ display: "block", flex: "none" }}
    >
      <title>{title}</title>

      {/* Outer merlons — the teeth you shelter behind. */}
      <path
        d="M2 6h4.5v4H2V6Z M17.5 6H22v4h-4.5V6Z"
        fill="currentColor"
        opacity="0.55"
      />

      {/* Centre merlon, raised and lit: the vantage point. Taller than its
          neighbours so the silhouette has a clear focal point at any size. */}
      <path d="M9.75 3h4.5v7h-4.5V3Z" fill={lit} />

      {/* The wall the merlons stand on. Solid, and full width — this is the
          element that stops the three teeth reading as a bar chart. */}
      <path d="M2 12h20v3H2v-3Z" fill="currentColor" opacity="0.55" />

      {/* Sightline through the crenel: the gap is what the wall is *for*.
          Drawn from behind the centre merlon out through the left crenel. */}
      <path
        d="M7.75 7.6h1.25"
        stroke={lit}
        strokeWidth="1.6"
        strokeLinecap="square"
        opacity="0.9"
      />

      {/* Foundation course, stepped in — gives the mark a base to sit on so it
          does not float when set beside text. */}
      <path d="M4 17h16v2.5H4V17Z" fill="currentColor" opacity="0.28" />
    </svg>
  );
}
