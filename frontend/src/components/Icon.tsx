/** Material Symbols icon, referenced by its ligature name (https://fonts.google.com/icons). */
export function Icon({ name, size = 18, filled = false }: { name: string; size?: number; filled?: boolean }) {
  return (
    <span
      className="material-symbols-outlined"
      aria-hidden="true"
      style={{ fontSize: size, fontVariationSettings: `"FILL" ${filled ? 1 : 0}, "wght" 400, "GRAD" 0, "opsz" 24` }}
    >
      {name}
    </span>
  );
}
