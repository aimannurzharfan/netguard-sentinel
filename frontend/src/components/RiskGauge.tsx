import { clamp, riskTier } from "@/lib/format"

const SEGMENTS = 40
const CX = 100
const CY = 100
const INNER_R = 64
const OUTER_R = 86

function polar(radius: number, angleDeg: number) {
  const a = (angleDeg * Math.PI) / 180
  return { x: CX + radius * Math.cos(a), y: CY - radius * Math.sin(a) }
}

// A segment's hue follows its own position on the meter so the arc reads as a
// spectrum (green -> amber -> red), the way a physical threat gauge would.
function tickColor(value: number): string {
  if (value >= 80) return "var(--critical)"
  if (value >= 60) return "var(--high)"
  if (value >= 35) return "var(--medium)"
  return "var(--low)"
}

export function RiskGauge({ score }: { score: number }) {
  const value = clamp(score)
  const tier = riskTier(value)
  const filled = Math.round((value / 100) * SEGMENTS)

  const ticks = Array.from({ length: SEGMENTS }, (_, i) => {
    const angle = 180 - (i / (SEGMENTS - 1)) * 180
    const p1 = polar(INNER_R, angle)
    const p2 = polar(OUTER_R, angle)
    const tickValue = (i / (SEGMENTS - 1)) * 100
    const isOn = i < filled
    return (
      <line
        key={i}
        x1={p1.x}
        y1={p1.y}
        x2={p2.x}
        y2={p2.y}
        stroke={isOn ? tickColor(tickValue) : "var(--border)"}
        strokeWidth={3}
        strokeLinecap="round"
        opacity={isOn ? 1 : 0.55}
        style={{
          transition: "opacity 360ms ease",
          transitionDelay: `${i * 14}ms`,
        }}
      />
    )
  })

  return (
    <figure
      className="flex flex-col items-center"
      role="img"
      aria-label={`Host risk score ${value} out of 100. ${tier.label}.`}
    >
      <svg
        viewBox="0 0 200 118"
        className="w-[200px] max-w-full"
        aria-hidden="true"
      >
        {ticks}
        <text
          x={CX}
          y={86}
          textAnchor="middle"
          className="font-display"
          style={{
            fontSize: "38px",
            fontWeight: 700,
            fill: "var(--foreground)",
            fontVariantNumeric: "tabular-nums",
          }}
        >
          {value}
        </text>
        <text
          x={CX}
          y={104}
          textAnchor="middle"
          style={{
            fontSize: "10px",
            letterSpacing: "0.18em",
            fill: "var(--muted-foreground)",
          }}
        >
          / 100 RISK
        </text>
      </svg>
      <figcaption
        className="tactical-label mt-1 text-[0.72rem]"
        style={{ color: `var(--${tier.token})` }}
      >
        {tier.label}
      </figcaption>
    </figure>
  )
}
